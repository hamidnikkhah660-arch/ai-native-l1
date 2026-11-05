//! CP-0392 candidate: canonical v0.4 Genesis manifest.
//!
//! This binds a network ID, an explicitly supplied owner account ID, the v0.4 policy
//! fingerprint, initial owner credit, bucket issuance counters, and the initial state root into
//! canonical fixed-width bytes. No key is generated here. This remains a candidate manifest:
//! it is not yet the Genesis loader for the live node, not yet bound to the production block
//! producer/importer, and not an activation decision for mainnet.

use sha2::{Digest, Sha256};

use crate::monetary_allocation_v04_candidate::{
    policy_fingerprint, AllocationAccounting, AllocationAccountingError, AllocationBucket,
    ACCOUNTING_BYTES,
};

pub const GENESIS_MAGIC: [u8; 4] = *b"QZGM";
pub const GENESIS_FORMAT_VERSION: u16 = 1;
pub const NATIVE_PROTOCOL_VERSION_V04: u16 = 4;
pub const GENESIS_MANIFEST_BYTES: usize = 4 + 2 + 2 + 32 + 32 + 32 + ACCOUNTING_BYTES + 32;

const V04_MONETARY_STATE_ROOT_DOMAIN: &[u8] = b"QUANTUMZXB-MONETARY-STATE-ROOT-V04\0";
const GENESIS_MANIFEST_HASH_DOMAIN: &[u8] = b"QUANTUMZXB-GENESIS-MANIFEST-HASH-V04\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisManifestError {
    WrongLength,
    WrongMagic,
    UnsupportedFormatVersion,
    UnsupportedProtocolVersion,
    ZeroNetworkId,
    ZeroOwnerAccount,
    PolicyFingerprintMismatch,
    InvalidInitialAllocation,
    InvalidStateRoot,
    Allocation(AllocationAccountingError),
}

impl From<AllocationAccountingError> for GenesisManifestError {
    fn from(value: AllocationAccountingError) -> Self {
        Self::Allocation(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisManifestV04 {
    network_id: [u8; 32],
    owner_account: [u8; 32],
    policy_digest: [u8; 32],
    initial_accounting: AllocationAccounting,
    initial_state_root: [u8; 32],
}

impl GenesisManifestV04 {
    /// Build the proposed v0.4 Genesis with the full 1B owner allocation credited.
    /// The owner account must come from a separate verified key/custody decision.
    /// No private key is generated, imported, or stored by this constructor.
    pub fn new(
        network_id: [u8; 32],
        owner_account: [u8; 32],
    ) -> Result<Self, GenesisManifestError> {
        if network_id.iter().all(|byte| *byte == 0) {
            return Err(GenesisManifestError::ZeroNetworkId);
        }
        if owner_account.iter().all(|byte| *byte == 0) {
            return Err(GenesisManifestError::ZeroOwnerAccount);
        }
        let mut initial_accounting = AllocationAccounting::new();
        initial_accounting.record_issuance(
            AllocationBucket::OwnerAllocation,
            AllocationBucket::OwnerAllocation.budget().atoms(),
        )?;
        let policy_digest = policy_fingerprint();
        let initial_state_root = Self::compute_state_root(
            &network_id,
            &owner_account,
            &policy_digest,
            &initial_accounting,
        )?;
        let manifest = Self {
            network_id,
            owner_account,
            policy_digest,
            initial_accounting,
            initial_state_root,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn network_id(&self) -> &[u8; 32] {
        &self.network_id
    }

    pub fn owner_account(&self) -> &[u8; 32] {
        &self.owner_account
    }

    pub fn policy_digest(&self) -> &[u8; 32] {
        &self.policy_digest
    }

    pub fn initial_state_root(&self) -> &[u8; 32] {
        &self.initial_state_root
    }

    pub fn initial_owner_balance_atoms(&self) -> u128 {
        self.initial_accounting
            .issued_by_bucket_atoms(AllocationBucket::OwnerAllocation)
    }

    pub fn initial_gross_issued_atoms(&self) -> Result<u128, GenesisManifestError> {
        Ok(self.initial_accounting.gross_issued_atoms()?)
    }

    pub fn initial_live_supply_atoms(&self) -> Result<u128, GenesisManifestError> {
        Ok(self.initial_accounting.live_supply_atoms()?)
    }

    pub fn accounting(&self) -> &AllocationAccounting {
        &self.initial_accounting
    }

    fn compute_state_root(
        network_id: &[u8; 32],
        owner_account: &[u8; 32],
        policy_digest: &[u8; 32],
        accounting: &AllocationAccounting,
    ) -> Result<[u8; 32], GenesisManifestError> {
        let owner_balance = u64::try_from(AllocationBucket::OwnerAllocation.budget().atoms())
            .map_err(|_| GenesisManifestError::InvalidInitialAllocation)?;
        let ledger = crate::state_machine::LedgerState::genesis(
            *network_id,
            vec![(*owner_account, owner_balance)],
        )
        .map_err(|_| GenesisManifestError::InvalidInitialAllocation)?;
        let ledger_root = ledger.state_root();
        let accounting_commitment = accounting.commitment()?;
        let mined = 0u128.to_be_bytes();
        let mut hash = Sha256::new();
        hash.update(V04_MONETARY_STATE_ROOT_DOMAIN);
        hash.update(policy_digest);
        hash.update(ledger_root);
        hash.update(accounting_commitment);
        hash.update(mined);
        Ok(hash.finalize().into())
    }
    pub fn validate(&self) -> Result<(), GenesisManifestError> {
        if self.network_id.iter().all(|byte| *byte == 0) {
            return Err(GenesisManifestError::ZeroNetworkId);
        }
        if self.owner_account.iter().all(|byte| *byte == 0) {
            return Err(GenesisManifestError::ZeroOwnerAccount);
        }
        if self.policy_digest != policy_fingerprint() {
            return Err(GenesisManifestError::PolicyFingerprintMismatch);
        }
        self.initial_accounting.validate()?;
        if self.initial_accounting.burned_atoms() != 0
            || self
                .initial_accounting
                .issued_by_bucket_atoms(AllocationBucket::OwnerAllocation)
                != AllocationBucket::OwnerAllocation.budget().atoms()
            || AllocationBucket::ALL
                .into_iter()
                .filter(|bucket| *bucket != AllocationBucket::OwnerAllocation)
                .any(|bucket| self.initial_accounting.issued_by_bucket_atoms(bucket) != 0)
            || self.initial_accounting.gross_issued_atoms()?
                != AllocationBucket::OwnerAllocation.budget().atoms()
        {
            return Err(GenesisManifestError::InvalidInitialAllocation);
        }
        let expected_root = Self::compute_state_root(
            &self.network_id,
            &self.owner_account,
            &self.policy_digest,
            &self.initial_accounting,
        )?;
        if self.initial_state_root != expected_root {
            return Err(GenesisManifestError::InvalidStateRoot);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<[u8; GENESIS_MANIFEST_BYTES], GenesisManifestError> {
        self.validate()?;
        let accounting = self.initial_accounting.encode()?;
        let mut bytes = Vec::with_capacity(GENESIS_MANIFEST_BYTES);
        bytes.extend_from_slice(&GENESIS_MAGIC);
        bytes.extend_from_slice(&GENESIS_FORMAT_VERSION.to_be_bytes());
        bytes.extend_from_slice(&NATIVE_PROTOCOL_VERSION_V04.to_be_bytes());
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.owner_account);
        bytes.extend_from_slice(&self.policy_digest);
        bytes.extend_from_slice(&accounting);
        bytes.extend_from_slice(&self.initial_state_root);
        bytes
            .try_into()
            .map_err(|_| GenesisManifestError::WrongLength)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, GenesisManifestError> {
        if bytes.len() != GENESIS_MANIFEST_BYTES {
            return Err(GenesisManifestError::WrongLength);
        }
        if bytes[..4] != GENESIS_MAGIC {
            return Err(GenesisManifestError::WrongMagic);
        }
        if u16::from_be_bytes([bytes[4], bytes[5]]) != GENESIS_FORMAT_VERSION {
            return Err(GenesisManifestError::UnsupportedFormatVersion);
        }
        if u16::from_be_bytes([bytes[6], bytes[7]]) != NATIVE_PROTOCOL_VERSION_V04 {
            return Err(GenesisManifestError::UnsupportedProtocolVersion);
        }

        let network_id = read_array::<32>(bytes, 8)?;
        let owner_account = read_array::<32>(bytes, 40)?;
        let policy_digest = read_array::<32>(bytes, 72)?;
        let accounting_start = 104;
        let accounting_end = accounting_start + ACCOUNTING_BYTES;
        let initial_accounting =
            AllocationAccounting::decode(&bytes[accounting_start..accounting_end])?;
        let initial_state_root = read_array::<32>(bytes, accounting_end)?;

        let manifest = Self {
            network_id,
            owner_account,
            policy_digest,
            initial_accounting,
            initial_state_root,
        };
        manifest.validate()?;
        if manifest.encode()?.as_slice() != bytes {
            return Err(GenesisManifestError::WrongLength);
        }
        Ok(manifest)
    }

    pub fn manifest_hash(&self) -> Result<[u8; 32], GenesisManifestError> {
        let encoded = self.encode()?;
        let mut hash = Sha256::new();
        hash.update(GENESIS_MANIFEST_HASH_DOMAIN);
        hash.update(encoded);
        Ok(hash.finalize().into())
    }
}

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], GenesisManifestError> {
    bytes
        .get(offset..offset + N)
        .ok_or(GenesisManifestError::WrongLength)?
        .try_into()
        .map_err(|_| GenesisManifestError::WrongLength)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monetary_allocation_v04_candidate::ATOMS_PER_COIN;

    const NETWORK: [u8; 32] = [0x31; 32];
    const OWNER: [u8; 32] = [0xA7; 32];

    #[test]
    fn genesis_manifest_roundtrips_and_credits_only_one_billion_owner_coins() {
        let manifest = GenesisManifestV04::new(NETWORK, OWNER).unwrap();
        assert_eq!(
            manifest.initial_owner_balance_atoms(),
            1_000_000_000 * ATOMS_PER_COIN
        );
        assert_eq!(
            manifest.initial_gross_issued_atoms().unwrap(),
            1_000_000_000 * ATOMS_PER_COIN
        );
        assert_eq!(
            manifest.initial_live_supply_atoms().unwrap(),
            1_000_000_000 * ATOMS_PER_COIN
        );
        for bucket in AllocationBucket::ALL {
            let expected = if bucket == AllocationBucket::OwnerAllocation {
                bucket.budget().atoms()
            } else {
                0
            };
            assert_eq!(
                manifest.accounting().issued_by_bucket_atoms(bucket),
                expected
            );
        }
        let bytes = manifest.encode().unwrap();
        assert_eq!(bytes.len(), GENESIS_MANIFEST_BYTES);
        assert_eq!(GenesisManifestV04::decode(&bytes).unwrap(), manifest);
        assert_ne!(manifest.manifest_hash().unwrap(), [0; 32]);
    }

    #[test]
    fn genesis_manifest_rejects_zero_network_or_owner_and_wrong_versions() {
        assert_eq!(
            GenesisManifestV04::new([0; 32], OWNER),
            Err(GenesisManifestError::ZeroNetworkId)
        );
        assert_eq!(
            GenesisManifestV04::new(NETWORK, [0; 32]),
            Err(GenesisManifestError::ZeroOwnerAccount)
        );
        let manifest = GenesisManifestV04::new(NETWORK, OWNER).unwrap();
        let bytes = manifest.encode().unwrap();

        let mut wrong_format = bytes;
        wrong_format[5] ^= 1;
        assert_eq!(
            GenesisManifestV04::decode(&wrong_format),
            Err(GenesisManifestError::UnsupportedFormatVersion)
        );

        let mut wrong_protocol = bytes;
        wrong_protocol[7] ^= 1;
        assert_eq!(
            GenesisManifestV04::decode(&wrong_protocol),
            Err(GenesisManifestError::UnsupportedProtocolVersion)
        );
    }

    #[test]
    fn genesis_manifest_rejects_network_owner_policy_accounting_and_root_tampering() {
        let manifest = GenesisManifestV04::new(NETWORK, OWNER).unwrap();
        let bytes = manifest.encode().unwrap();

        for offset in [8usize, 40, 72, 104, 254] {
            let mut altered = bytes;
            altered[offset] ^= 0x80;
            assert!(
                GenesisManifestV04::decode(&altered).is_err(),
                "tampering at byte {offset} must fail closed"
            );
        }
        assert_eq!(
            GenesisManifestV04::decode(&bytes[..bytes.len() - 1]),
            Err(GenesisManifestError::WrongLength)
        );
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert_eq!(
            GenesisManifestV04::decode(&trailing),
            Err(GenesisManifestError::WrongLength)
        );
    }

    #[test]
    fn genesis_manifest_is_stable_for_identical_inputs_and_domain_separated() {
        let first = GenesisManifestV04::new(NETWORK, OWNER).unwrap();
        let second = GenesisManifestV04::new(NETWORK, OWNER).unwrap();
        let other_network = GenesisManifestV04::new([0x32; 32], OWNER).unwrap();
        let other_owner = GenesisManifestV04::new(NETWORK, [0xA8; 32]).unwrap();
        assert_eq!(first.encode().unwrap(), second.encode().unwrap());
        assert_eq!(
            first.manifest_hash().unwrap(),
            second.manifest_hash().unwrap()
        );
        assert_ne!(
            first.manifest_hash().unwrap(),
            other_network.manifest_hash().unwrap()
        );
        assert_ne!(
            first.manifest_hash().unwrap(),
            other_owner.manifest_hash().unwrap()
        );
    }

    #[test]
    fn independent_python_golden_vectors_match_every_v04_genesis_commitment() {
        const VECTORS: &str =
            include_str!("../../../../simulations/quantumzxb_v04_genesis_vectors.txt");
        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|byte| format!("{byte:02x}")).collect()
        }
        let records: std::collections::BTreeMap<&str, &str> = VECTORS
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.split_once('|').expect("vector key/value separator"))
            .collect();
        let expected = |key: &str| *records.get(key).expect("required vector field");
        let manifest = GenesisManifestV04::new(NETWORK, OWNER).unwrap();

        assert_eq!(hex(manifest.network_id()), expected("network_id"));
        assert_eq!(hex(manifest.owner_account()), expected("owner_account"));
        assert_eq!(
            hex(manifest.policy_digest()),
            expected("policy_fingerprint")
        );
        assert_eq!(
            hex(&manifest.accounting().encode().unwrap()),
            expected("initial_accounting")
        );
        assert_eq!(
            hex(&manifest.accounting().commitment().unwrap()),
            expected("accounting_commitment")
        );
        assert_eq!(
            hex(manifest.initial_state_root()),
            expected("genesis_state_root")
        );
        assert_eq!(
            hex(&manifest.encode().unwrap()),
            expected("genesis_manifest_bytes")
        );
        assert_eq!(
            hex(&manifest.manifest_hash().unwrap()),
            expected("genesis_manifest_hash")
        );
        assert_eq!(
            records.len(),
            8,
            "fixture has no missing or duplicate vector keys"
        );
    }
}
