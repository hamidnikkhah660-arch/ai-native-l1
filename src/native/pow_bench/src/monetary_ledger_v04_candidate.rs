//! CP-0393 bridge from the proposed v0.4 Genesis manifest to the real ledger substrate.
//!
//! This confirms that the v0.4 manifest's initial state root is the same root derived from the
//! existing deterministic account ledger plus v0.4 allocation counters. It does not yet implement
//! block transitions, issuance authorization, snapshots, fork-choice/reorg, durable-store or
//! node-runtime integration; those are subsequent Gate 2 acceptance items.

use sha2::{Digest, Sha256};

use crate::{
    monetary_allocation_v04_candidate::{
        policy_fingerprint, AllocationAccounting, AllocationBucket, MAX_TOTAL_SUPPLY_ATOMS,
    },
    monetary_genesis_v04_candidate::{GenesisManifestError, GenesisManifestV04},
    state_machine::{LedgerState, StateError},
};

const V04_MONETARY_STATE_ROOT_DOMAIN: &[u8] = b"QUANTUMZXB-MONETARY-STATE-ROOT-V04\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V04LedgerGenesisError {
    Manifest(GenesisManifestError),
    State(StateError),
    InitialSupplyMismatch,
    MiningCounterMismatch,
    StateRootMismatch,
    SupplyCapExceeded,
}

impl From<GenesisManifestError> for V04LedgerGenesisError {
    fn from(value: GenesisManifestError) -> Self {
        Self::Manifest(value)
    }
}

impl From<StateError> for V04LedgerGenesisError {
    fn from(value: StateError) -> Self {
        Self::State(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonetaryLedgerStateV04Candidate {
    ledger: LedgerState,
    allocation_accounting: AllocationAccounting,
    total_mined_atoms: u128,
}

impl MonetaryLedgerStateV04Candidate {
    /// Materialize the manifest's only initially issued bucket into the deterministic account
    /// ledger and prove that its state root equals the manifest root byte-for-byte.
    pub fn from_genesis_manifest(
        manifest: &GenesisManifestV04,
    ) -> Result<Self, V04LedgerGenesisError> {
        manifest.validate()?;
        let owner_balance = u64::try_from(manifest.initial_owner_balance_atoms())
            .map_err(|_| V04LedgerGenesisError::InitialSupplyMismatch)?;
        let ledger = LedgerState::genesis(
            *manifest.network_id(),
            vec![(*manifest.owner_account(), owner_balance)],
        )?;
        let candidate = Self {
            ledger,
            allocation_accounting: manifest.accounting().clone(),
            total_mined_atoms: 0,
        };
        candidate.validate()?;
        if candidate.state_root()? != *manifest.initial_state_root() {
            return Err(V04LedgerGenesisError::StateRootMismatch);
        }
        Ok(candidate)
    }

    pub fn ledger(&self) -> &LedgerState {
        &self.ledger
    }

    pub fn allocation_accounting(&self) -> &AllocationAccounting {
        &self.allocation_accounting
    }

    pub fn total_mined_atoms(&self) -> u128 {
        self.total_mined_atoms
    }

    pub fn total_value_atoms(&self) -> Result<u128, V04LedgerGenesisError> {
        Ok(self.ledger.total_value()?)
    }

    /// State root commits to the normal deterministic ledger root, v0.4 policy, per-bucket
    /// counters/burn counter, and cumulative miner issuance. It excludes tip hash through the
    /// underlying LedgerState root to avoid a root/hash cycle.
    pub fn state_root(&self) -> Result<[u8; 32], V04LedgerGenesisError> {
        let policy = policy_fingerprint();
        let ledger_root = self.ledger.state_root();
        let allocation_commitment = self.allocation_accounting.commitment().map_err(|error| {
            V04LedgerGenesisError::Manifest(GenesisManifestError::Allocation(error))
        })?;
        let mined = self.total_mined_atoms.to_be_bytes();
        let mut hash = Sha256::new();
        hash.update(V04_MONETARY_STATE_ROOT_DOMAIN);
        hash.update(policy);
        hash.update(ledger_root);
        hash.update(allocation_commitment);
        hash.update(mined);
        Ok(hash.finalize().into())
    }

    pub fn validate(&self) -> Result<(), V04LedgerGenesisError> {
        self.allocation_accounting.validate().map_err(|error| {
            V04LedgerGenesisError::Manifest(GenesisManifestError::Allocation(error))
        })?;
        if self.total_mined_atoms
            != self
                .allocation_accounting
                .issued_by_bucket_atoms(AllocationBucket::MiningNetworkSecurity)
        {
            return Err(V04LedgerGenesisError::MiningCounterMismatch);
        }
        let live_supply = self
            .allocation_accounting
            .live_supply_atoms()
            .map_err(|error| {
                V04LedgerGenesisError::Manifest(GenesisManifestError::Allocation(error))
            })?;
        let account_total = self.ledger.total_value()?;
        if account_total != live_supply {
            return Err(V04LedgerGenesisError::InitialSupplyMismatch);
        }
        if self
            .allocation_accounting
            .gross_issued_atoms()
            .map_err(|error| {
                V04LedgerGenesisError::Manifest(GenesisManifestError::Allocation(error))
            })?
            > MAX_TOTAL_SUPPLY_ATOMS
        {
            return Err(V04LedgerGenesisError::SupplyCapExceeded);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETWORK: [u8; 32] = [0x31; 32];
    const OWNER: [u8; 32] = [0xA7; 32];

    #[test]
    fn v04_genesis_materializes_exactly_the_manifest_owner_credit_and_state_root() {
        let manifest = GenesisManifestV04::new(NETWORK, OWNER).unwrap();
        let state = MonetaryLedgerStateV04Candidate::from_genesis_manifest(&manifest).unwrap();
        assert_eq!(
            state.total_value_atoms().unwrap(),
            1_000_000_000u128 * crate::monetary_allocation_v04_candidate::ATOMS_PER_COIN
        );
        assert_eq!(
            state
                .allocation_accounting()
                .issued_by_bucket_atoms(AllocationBucket::OwnerAllocation),
            state.total_value_atoms().unwrap()
        );
        assert_eq!(state.total_mined_atoms(), 0);
        assert_eq!(state.state_root().unwrap(), *manifest.initial_state_root());
        state.validate().unwrap();
    }

    #[test]
    fn v04_genesis_is_network_and_owner_bound() {
        let manifest_a = GenesisManifestV04::new(NETWORK, OWNER).unwrap();
        let manifest_b = GenesisManifestV04::new([0x32; 32], OWNER).unwrap();
        let manifest_c = GenesisManifestV04::new(NETWORK, [0xA8; 32]).unwrap();
        let state_a = MonetaryLedgerStateV04Candidate::from_genesis_manifest(&manifest_a).unwrap();
        let state_b = MonetaryLedgerStateV04Candidate::from_genesis_manifest(&manifest_b).unwrap();
        let state_c = MonetaryLedgerStateV04Candidate::from_genesis_manifest(&manifest_c).unwrap();
        assert_ne!(state_a.state_root().unwrap(), state_b.state_root().unwrap());
        assert_ne!(state_a.state_root().unwrap(), state_c.state_root().unwrap());
    }

    #[test]
    fn old_legacy_monetary_genesis_is_not_implicitly_used_for_v04() {
        let manifest = GenesisManifestV04::new(NETWORK, OWNER).unwrap();
        let state = MonetaryLedgerStateV04Candidate::from_genesis_manifest(&manifest).unwrap();
        assert_eq!(
            state.total_value_atoms().unwrap(),
            1_000_000_000u128 * crate::monetary_allocation_v04_candidate::ATOMS_PER_COIN
        );
        assert_ne!(
            state.total_value_atoms().unwrap(),
            crate::state_machine::MONETARY_FOUNDER_ALLOCATION_ATOMS
                + crate::state_machine::MONETARY_PUBLIC_GOODS_BUDGET_ATOMS
        );
    }
}
