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

/// Candidate-only versioned snapshot wrapper for the v0.4 monetary ledger.
/// The snapshot binds the underlying deterministic ledger, all allocation counters,
/// cumulative mining issuance, and the v0.4 monetary state root under a checksum.
pub const V04_LEDGER_SNAPSHOT_MAGIC: [u8; 4] = *b"QZL4";
pub const V04_LEDGER_SNAPSHOT_VERSION: u16 = 1;
const V04_LEDGER_SNAPSHOT_CHECKSUM_DOMAIN: &[u8] = b"QUANTUMZXB-MONETARY-SNAPSHOT-CHECK-V04\0";
const V04_LEDGER_SNAPSHOT_HEADER_BYTES: usize = 4 + 2 + 32 + 4;
const V04_LEDGER_SNAPSHOT_FIXED_OVERHEAD: usize = V04_LEDGER_SNAPSHOT_HEADER_BYTES
    + crate::monetary_allocation_v04_candidate::ACCOUNTING_BYTES
    + 16
    + 32
    + 32;
pub const MAX_ENCODED_V04_LEDGER_SNAPSHOT_BYTES: usize =
    crate::state_machine::MAX_ENCODED_SNAPSHOT_BYTES + V04_LEDGER_SNAPSHOT_FIXED_OVERHEAD;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V04LedgerSnapshotError {
    Incomplete,
    WrongLength,
    WrongMagic,
    UnsupportedVersion,
    InvalidNetworkId,
    NetworkMismatch,
    ChecksumMismatch,
    Oversize,
    LengthOverflow,
    Ledger(StateError),
    Accounting(crate::monetary_allocation_v04_candidate::AllocationAccountingError),
    InvalidState(V04LedgerGenesisError),
    StateRootMismatch,
}

fn v04_ledger_snapshot_checksum(preimage: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(V04_LEDGER_SNAPSHOT_CHECKSUM_DOMAIN);
    hash.update(preimage);
    hash.finalize().into()
}

impl MonetaryLedgerStateV04Candidate {
    /// Encode a restart snapshot with strict framing, network binding, and an outer checksum.
    /// The checksum detects corruption; it is not a signature or anti-rollback guarantee.
    pub fn encode_snapshot(&self) -> Result<Vec<u8>, V04LedgerSnapshotError> {
        self.validate()
            .map_err(V04LedgerSnapshotError::InvalidState)?;
        let ledger_bytes = self
            .ledger
            .encode_snapshot()
            .map_err(V04LedgerSnapshotError::Ledger)?;
        let ledger_length = u32::try_from(ledger_bytes.len())
            .map_err(|_| V04LedgerSnapshotError::LengthOverflow)?;
        let accounting_bytes = self
            .allocation_accounting
            .encode()
            .map_err(V04LedgerSnapshotError::Accounting)?;
        let state_root = self
            .state_root()
            .map_err(V04LedgerSnapshotError::InvalidState)?;

        let mut bytes = Vec::with_capacity(
            V04_LEDGER_SNAPSHOT_FIXED_OVERHEAD
                .checked_add(ledger_bytes.len())
                .ok_or(V04LedgerSnapshotError::LengthOverflow)?,
        );
        bytes.extend_from_slice(&V04_LEDGER_SNAPSHOT_MAGIC);
        bytes.extend_from_slice(&V04_LEDGER_SNAPSHOT_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.ledger.network_id());
        bytes.extend_from_slice(&ledger_length.to_be_bytes());
        bytes.extend_from_slice(&ledger_bytes);
        bytes.extend_from_slice(&accounting_bytes);
        bytes.extend_from_slice(&self.total_mined_atoms.to_be_bytes());
        bytes.extend_from_slice(&state_root);

        let total_length = bytes
            .len()
            .checked_add(32)
            .ok_or(V04LedgerSnapshotError::LengthOverflow)?;
        if total_length > MAX_ENCODED_V04_LEDGER_SNAPSHOT_BYTES {
            return Err(V04LedgerSnapshotError::Oversize);
        }
        let checksum = v04_ledger_snapshot_checksum(&bytes);
        bytes.extend_from_slice(&checksum);
        Ok(bytes)
    }

    /// Restore only a complete, checksummed, canonical snapshot for the expected network.
    /// Every counter and the state root are independently revalidated after decoding.
    pub fn decode_snapshot(
        bytes: &[u8],
        expected_network_id: &[u8; 32],
    ) -> Result<Self, V04LedgerSnapshotError> {
        if expected_network_id.iter().all(|byte| *byte == 0) {
            return Err(V04LedgerSnapshotError::InvalidNetworkId);
        }
        if bytes.len() > MAX_ENCODED_V04_LEDGER_SNAPSHOT_BYTES {
            return Err(V04LedgerSnapshotError::Oversize);
        }
        if bytes.len() < V04_LEDGER_SNAPSHOT_FIXED_OVERHEAD {
            return Err(V04LedgerSnapshotError::Incomplete);
        }

        let checksum_start = bytes.len() - 32;
        let expected_checksum = v04_ledger_snapshot_checksum(&bytes[..checksum_start]);
        if bytes[checksum_start..] != expected_checksum {
            return Err(V04LedgerSnapshotError::ChecksumMismatch);
        }

        let payload = &bytes[..checksum_start];
        if payload[..4] != V04_LEDGER_SNAPSHOT_MAGIC {
            return Err(V04LedgerSnapshotError::WrongMagic);
        }
        let version = u16::from_be_bytes([payload[4], payload[5]]);
        if version != V04_LEDGER_SNAPSHOT_VERSION {
            return Err(V04LedgerSnapshotError::UnsupportedVersion);
        }
        let network_id: [u8; 32] = payload[6..38]
            .try_into()
            .map_err(|_| V04LedgerSnapshotError::WrongLength)?;
        if network_id.iter().all(|byte| *byte == 0) {
            return Err(V04LedgerSnapshotError::InvalidNetworkId);
        }
        if &network_id != expected_network_id {
            return Err(V04LedgerSnapshotError::NetworkMismatch);
        }

        let ledger_length = u32::from_be_bytes(
            payload[38..42]
                .try_into()
                .map_err(|_| V04LedgerSnapshotError::WrongLength)?,
        ) as usize;
        let expected_payload_length = V04_LEDGER_SNAPSHOT_HEADER_BYTES
            .checked_add(ledger_length)
            .and_then(|value| {
                value.checked_add(crate::monetary_allocation_v04_candidate::ACCOUNTING_BYTES)
            })
            .and_then(|value| value.checked_add(16 + 32))
            .ok_or(V04LedgerSnapshotError::LengthOverflow)?;
        if payload.len() != expected_payload_length {
            return Err(V04LedgerSnapshotError::WrongLength);
        }

        let ledger_start = V04_LEDGER_SNAPSHOT_HEADER_BYTES;
        let ledger_end = ledger_start
            .checked_add(ledger_length)
            .ok_or(V04LedgerSnapshotError::LengthOverflow)?;
        let ledger = LedgerState::decode_snapshot(&payload[ledger_start..ledger_end], &network_id)
            .map_err(V04LedgerSnapshotError::Ledger)?;

        let accounting_end = ledger_end
            .checked_add(crate::monetary_allocation_v04_candidate::ACCOUNTING_BYTES)
            .ok_or(V04LedgerSnapshotError::LengthOverflow)?;
        let allocation_accounting =
            AllocationAccounting::decode(&payload[ledger_end..accounting_end])
                .map_err(V04LedgerSnapshotError::Accounting)?;
        let total_mined_atoms = u128::from_be_bytes(
            payload[accounting_end..accounting_end + 16]
                .try_into()
                .map_err(|_| V04LedgerSnapshotError::WrongLength)?,
        );
        let committed_state_root: [u8; 32] = payload[accounting_end + 16..accounting_end + 48]
            .try_into()
            .map_err(|_| V04LedgerSnapshotError::WrongLength)?;

        let restored = Self {
            ledger,
            allocation_accounting,
            total_mined_atoms,
        };
        restored
            .validate()
            .map_err(V04LedgerSnapshotError::InvalidState)?;
        if restored
            .state_root()
            .map_err(V04LedgerSnapshotError::InvalidState)?
            != committed_state_root
        {
            return Err(V04LedgerSnapshotError::StateRootMismatch);
        }
        Ok(restored)
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

    fn reseal_snapshot(bytes: &mut [u8]) {
        let checksum_start = bytes.len() - 32;
        let checksum = v04_ledger_snapshot_checksum(&bytes[..checksum_start]);
        bytes[checksum_start..].copy_from_slice(&checksum);
    }

    #[test]
    fn v04_snapshot_roundtrip_binds_ledger_accounting_and_monetary_root() {
        let manifest = GenesisManifestV04::new(NETWORK, OWNER).unwrap();
        let state = MonetaryLedgerStateV04Candidate::from_genesis_manifest(&manifest).unwrap();
        let encoded = state.encode_snapshot().unwrap();
        assert_eq!(&encoded[..4], &V04_LEDGER_SNAPSHOT_MAGIC);
        assert_eq!(
            u16::from_be_bytes([encoded[4], encoded[5]]),
            V04_LEDGER_SNAPSHOT_VERSION
        );
        let restored =
            MonetaryLedgerStateV04Candidate::decode_snapshot(&encoded, &NETWORK).unwrap();
        assert_eq!(restored, state);
        assert_eq!(restored.state_root().unwrap(), state.state_root().unwrap());
        assert_eq!(restored.encode_snapshot().unwrap(), encoded);
    }

    #[test]
    fn v04_snapshot_rejects_corruption_wrong_network_and_bad_framing() {
        let manifest = GenesisManifestV04::new(NETWORK, OWNER).unwrap();
        let state = MonetaryLedgerStateV04Candidate::from_genesis_manifest(&manifest).unwrap();
        let encoded = state.encode_snapshot().unwrap();

        let mut corrupt = encoded.clone();
        corrupt[50] ^= 1;
        assert_eq!(
            MonetaryLedgerStateV04Candidate::decode_snapshot(&corrupt, &NETWORK),
            Err(V04LedgerSnapshotError::ChecksumMismatch)
        );
        assert_eq!(
            MonetaryLedgerStateV04Candidate::decode_snapshot(&encoded, &[0x32; 32]),
            Err(V04LedgerSnapshotError::NetworkMismatch)
        );
        assert_eq!(
            MonetaryLedgerStateV04Candidate::decode_snapshot(&encoded, &[0; 32]),
            Err(V04LedgerSnapshotError::InvalidNetworkId)
        );
        assert!(matches!(
            MonetaryLedgerStateV04Candidate::decode_snapshot(
                &encoded[..encoded.len() - 1],
                &NETWORK
            ),
            Err(V04LedgerSnapshotError::ChecksumMismatch)
                | Err(V04LedgerSnapshotError::WrongLength)
        ));

        let mut unsupported = encoded.clone();
        unsupported[5] ^= 1;
        reseal_snapshot(&mut unsupported);
        assert_eq!(
            MonetaryLedgerStateV04Candidate::decode_snapshot(&unsupported, &NETWORK),
            Err(V04LedgerSnapshotError::UnsupportedVersion)
        );

        let mut length_mismatch = encoded;
        length_mismatch[41] ^= 1;
        reseal_snapshot(&mut length_mismatch);
        assert_eq!(
            MonetaryLedgerStateV04Candidate::decode_snapshot(&length_mismatch, &NETWORK),
            Err(V04LedgerSnapshotError::WrongLength)
        );
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
