//! CP-0651 fixed-supply policy for the QFP6 permissionless network.
//!
//! Total ceiling: 7B QZXB. Genesis owner allocation: 1B QZXB.
//! Six 1B accounting labels are committed as non-circulating, non-mintable
//! reserves. Block subsidy is permanently zero; producers earn transaction fees.
//! Any future release of a labelled reserve requires a separately versioned
//! governance/consensus policy and cannot be inferred from these accounting labels.

use sha2::{Digest, Sha256};

pub type Digest32 = [u8; 32];
pub type AccountId = [u8; 32];

pub const QZXB_ATOMS_PER_COIN: u128 = 100_000_000;
pub const CP0651_MAX_GROSS_ATOMS: u128 = 7_000_000_000u128 * QZXB_ATOMS_PER_COIN;
pub const CP0651_OWNER_GENESIS_ATOMS: u128 = 1_000_000_000u128 * QZXB_ATOMS_PER_COIN;
pub const CP0651_BLOCK_SUBSIDY_ATOMS: u128 = 0;
pub const CP0651_ACCOUNTING_LABEL_COUNT: usize = 6;
pub const CP0651_SNAPSHOT_BYTES: usize = 295;

const MAGIC: [u8; 4] = *b"Q651";
const VERSION: u16 = 1;
const CHECKSUM_DOMAIN: &[u8] = b"QRUN-V06-CP0651-SNAPSHOT-CHECKSUM-V1\0";
const POLICY_DOMAIN: &[u8] = b"QRUN-V06-CP0651-7B-OWNER-1B-SIX-LABELS-FEE-ONLY-V1\0";
const STATE_ROOT_DOMAIN: &[u8] = b"QRUN-V06-CP0651-SUPPLY-STATE-ROOT-V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Cp0651AccountingLabel {
    CommunityAirdrop = 0,
    ExchangeMarketLiquidity = 1,
    MarketingPartners = 2,
    DeveloperSecurityContributors = 3,
    FinancialStrategicSupporters = 4,
    ProtocolBurnReserve = 5,
}

impl Cp0651AccountingLabel {
    pub const ALL: [Self; CP0651_ACCOUNTING_LABEL_COUNT] = [
        Self::CommunityAirdrop,
        Self::ExchangeMarketLiquidity,
        Self::MarketingPartners,
        Self::DeveloperSecurityContributors,
        Self::FinancialStrategicSupporters,
        Self::ProtocolBurnReserve,
    ];

    pub const fn budget_atoms(self) -> u128 {
        1_000_000_000u128 * QZXB_ATOMS_PER_COIN
    }

    pub const fn tag(self) -> u8 {
        self as u8
    }

    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::CommunityAirdrop),
            1 => Some(Self::ExchangeMarketLiquidity),
            2 => Some(Self::MarketingPartners),
            3 => Some(Self::DeveloperSecurityContributors),
            4 => Some(Self::FinancialStrategicSupporters),
            5 => Some(Self::ProtocolBurnReserve),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cp0651Error {
    InvalidNetwork,
    InvalidOwner,
    InvalidHeight,
    InvalidAmount,
    WrongNetwork,
    LedgerSupplyMismatch { expected: u128, actual: u128 },
    SnapshotMalformed,
    SnapshotChecksumMismatch,
    SnapshotNonCanonical,
}

impl std::fmt::Display for Cp0651Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CP-0651 supply policy error: {self:?}")
    }
}
impl std::error::Error for Cp0651Error {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cp0651FixedSupply {
    network_id: Digest32,
    owner_account: AccountId,
    last_block_height: u64,
}

impl Cp0651FixedSupply {
    pub fn genesis(network_id: Digest32, owner_account: AccountId) -> Result<Self, Cp0651Error> {
        if network_id == [0; 32] {
            return Err(Cp0651Error::InvalidNetwork);
        }
        if owner_account == [0; 32] {
            return Err(Cp0651Error::InvalidOwner);
        }
        Ok(Self {
            network_id,
            owner_account,
            last_block_height: 0,
        })
    }

    pub fn network_id(&self) -> Digest32 {
        self.network_id
    }

    pub fn owner_account(&self) -> AccountId {
        self.owner_account
    }

    pub const fn owner_genesis_atoms(&self) -> u128 {
        CP0651_OWNER_GENESIS_ATOMS
    }

    pub const fn maximum_supply_atoms(&self) -> u128 {
        CP0651_MAX_GROSS_ATOMS
    }

    pub const fn block_subsidy_atoms(&self) -> u128 {
        CP0651_BLOCK_SUBSIDY_ATOMS
    }

    pub fn last_block_height(&self) -> u64 {
        self.last_block_height
    }

    pub fn accounting_label_budget_atoms(&self, label: Cp0651AccountingLabel) -> u128 {
        label.budget_atoms()
    }

    pub fn accounting_labels_total_atoms(&self) -> u128 {
        Cp0651AccountingLabel::ALL
            .iter()
            .map(|label| label.budget_atoms())
            .sum()
    }

    pub fn policy_fingerprint(&self) -> Digest32 {
        let mut hash = Sha256::new();
        hash.update(POLICY_DOMAIN);
        hash.update(self.network_id);
        hash.update(self.owner_account);
        hash.update(CP0651_MAX_GROSS_ATOMS.to_be_bytes());
        hash.update(CP0651_OWNER_GENESIS_ATOMS.to_be_bytes());
        hash.update(CP0651_BLOCK_SUBSIDY_ATOMS.to_be_bytes());
        hash.update((CP0651_ACCOUNTING_LABEL_COUNT as u32).to_be_bytes());
        for label in Cp0651AccountingLabel::ALL {
            hash.update([label.tag()]);
            hash.update(label.budget_atoms().to_be_bytes());
        }
        hash.finalize().into()
    }

    pub fn state_root(&self) -> Digest32 {
        let mut hash = Sha256::new();
        hash.update(STATE_ROOT_DOMAIN);
        hash.update(self.network_id);
        hash.update(self.owner_account);
        hash.update(self.policy_fingerprint());
        hash.update(self.last_block_height.to_be_bytes());
        hash.finalize().into()
    }

    /// A fixed-supply CP-0651 ledger starts with exactly the 1B owner allocation.
    /// Transaction fees are transfers within the existing supply and do not alter this total.
    pub fn validate_ledger_supply(&self, actual_atoms: u128) -> Result<(), Cp0651Error> {
        if actual_atoms != CP0651_OWNER_GENESIS_ATOMS {
            return Err(Cp0651Error::LedgerSupplyMismatch {
                expected: CP0651_OWNER_GENESIS_ATOMS,
                actual: actual_atoms,
            });
        }
        Ok(())
    }

    /// CP-0651 has no block subsidy. Heights remain sequentially committed so snapshots
    /// cannot be replayed with an arbitrarily advanced issuance cursor.
    pub fn expected_block_subsidy_atoms(&self, height: u64) -> Result<u128, Cp0651Error> {
        if height == 0 || height != self.last_block_height.saturating_add(1) {
            return Err(Cp0651Error::InvalidHeight);
        }
        Ok(CP0651_BLOCK_SUBSIDY_ATOMS)
    }

    pub fn record_block_subsidy(
        &mut self,
        height: u64,
        amount_atoms: u128,
    ) -> Result<(), Cp0651Error> {
        if amount_atoms != self.expected_block_subsidy_atoms(height)? {
            return Err(Cp0651Error::InvalidAmount);
        }
        self.last_block_height = height;
        Ok(())
    }

    pub fn encode_snapshot(&self) -> Result<[u8; CP0651_SNAPSHOT_BYTES], Cp0651Error> {
        self.validate_ledger_supply(CP0651_OWNER_GENESIS_ATOMS)?;
        let mut out = Vec::with_capacity(CP0651_SNAPSHOT_BYTES);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&self.network_id);
        out.extend_from_slice(&self.owner_account);
        out.extend_from_slice(&CP0651_MAX_GROSS_ATOMS.to_be_bytes());
        out.extend_from_slice(&CP0651_OWNER_GENESIS_ATOMS.to_be_bytes());
        out.extend_from_slice(&CP0651_BLOCK_SUBSIDY_ATOMS.to_be_bytes());
        out.push(CP0651_ACCOUNTING_LABEL_COUNT as u8);
        for label in Cp0651AccountingLabel::ALL {
            out.push(label.tag());
            out.extend_from_slice(&label.budget_atoms().to_be_bytes());
        }
        out.extend_from_slice(&self.last_block_height.to_be_bytes());
        out.extend_from_slice(&self.policy_fingerprint());
        if out.len() != CP0651_SNAPSHOT_BYTES - 32 {
            return Err(Cp0651Error::SnapshotMalformed);
        }
        let mut checksum = Sha256::new();
        checksum.update(CHECKSUM_DOMAIN);
        checksum.update(&out);
        out.extend_from_slice(&checksum.finalize());
        out.try_into().map_err(|_| Cp0651Error::SnapshotMalformed)
    }

    pub fn decode_snapshot(
        bytes: &[u8],
        expected_network_id: &Digest32,
    ) -> Result<Self, Cp0651Error> {
        if bytes.len() != CP0651_SNAPSHOT_BYTES
            || bytes[..4] != MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != VERSION
            || bytes[6..8] != [0, 0]
        {
            return Err(Cp0651Error::SnapshotMalformed);
        }
        if bytes[8..40] != expected_network_id[..] {
            return Err(Cp0651Error::WrongNetwork);
        }
        let payload_len = bytes.len() - 32;
        let mut checksum = Sha256::new();
        checksum.update(CHECKSUM_DOMAIN);
        checksum.update(&bytes[..payload_len]);
        if checksum.finalize().as_slice() != &bytes[payload_len..] {
            return Err(Cp0651Error::SnapshotChecksumMismatch);
        }
        let mut cursor = 40usize;
        let owner_account = take_array::<32>(bytes, &mut cursor)?;
        if take_u128(bytes, &mut cursor)? != CP0651_MAX_GROSS_ATOMS
            || take_u128(bytes, &mut cursor)? != CP0651_OWNER_GENESIS_ATOMS
            || take_u128(bytes, &mut cursor)? != CP0651_BLOCK_SUBSIDY_ATOMS
            || take_u8(bytes, &mut cursor)? as usize != CP0651_ACCOUNTING_LABEL_COUNT
        {
            return Err(Cp0651Error::SnapshotNonCanonical);
        }
        for expected in Cp0651AccountingLabel::ALL {
            if take_u8(bytes, &mut cursor)? != expected.tag()
                || take_u128(bytes, &mut cursor)? != expected.budget_atoms()
            {
                return Err(Cp0651Error::SnapshotNonCanonical);
            }
        }
        let last_block_height = take_u64(bytes, &mut cursor)?;
        let fingerprint = take_array::<32>(bytes, &mut cursor)?;
        if cursor != payload_len {
            return Err(Cp0651Error::SnapshotNonCanonical);
        }
        let state = Self {
            network_id: *expected_network_id,
            owner_account,
            last_block_height,
        };
        if state.policy_fingerprint() != fingerprint || state.encode_snapshot()?.as_slice() != bytes
        {
            return Err(Cp0651Error::SnapshotNonCanonical);
        }
        Ok(state)
    }
}

fn take_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], Cp0651Error> {
    let end = cursor
        .checked_add(N)
        .ok_or(Cp0651Error::SnapshotMalformed)?;
    let result = bytes
        .get(*cursor..end)
        .ok_or(Cp0651Error::SnapshotMalformed)?
        .try_into()
        .map_err(|_| Cp0651Error::SnapshotMalformed)?;
    *cursor = end;
    Ok(result)
}

fn take_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, Cp0651Error> {
    Ok(take_array::<1>(bytes, cursor)?[0])
}

fn take_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, Cp0651Error> {
    Ok(u64::from_be_bytes(take_array::<8>(bytes, cursor)?))
}

fn take_u128(bytes: &[u8], cursor: &mut usize) -> Result<u128, Cp0651Error> {
    Ok(u128::from_be_bytes(take_array::<16>(bytes, cursor)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETWORK: Digest32 = [0x51; 32];
    const OWNER: AccountId = [0x52; 32];

    #[test]
    fn supply_is_seven_billion_with_one_billion_owner_and_six_one_billion_labels() {
        let state = Cp0651FixedSupply::genesis(NETWORK, OWNER).unwrap();
        assert_eq!(state.maximum_supply_atoms(), 700_000_000_000_000_000);
        assert_eq!(state.owner_genesis_atoms(), 100_000_000_000_000_000);
        assert_eq!(
            state.accounting_labels_total_atoms(),
            600_000_000_000_000_000
        );
        assert_eq!(
            state.owner_genesis_atoms() + state.accounting_labels_total_atoms(),
            state.maximum_supply_atoms()
        );
        assert_eq!(state.block_subsidy_atoms(), 0);
        for label in Cp0651AccountingLabel::ALL {
            assert_eq!(
                state.accounting_label_budget_atoms(label),
                100_000_000_000_000_000
            );
        }
    }

    #[test]
    fn block_subsidy_is_zero_and_height_is_sequential() {
        let mut state = Cp0651FixedSupply::genesis(NETWORK, OWNER).unwrap();
        assert_eq!(state.expected_block_subsidy_atoms(1), Ok(0));
        assert!(matches!(
            state.expected_block_subsidy_atoms(2),
            Err(Cp0651Error::InvalidHeight)
        ));
        assert!(matches!(
            state.record_block_subsidy(1, 1),
            Err(Cp0651Error::InvalidAmount)
        ));
        assert_eq!(state.last_block_height(), 0);
        state.record_block_subsidy(1, 0).unwrap();
        assert_eq!(state.last_block_height(), 1);
    }

    #[test]
    fn snapshot_roundtrip_binds_owner_labels_network_and_policy() {
        let mut state = Cp0651FixedSupply::genesis(NETWORK, OWNER).unwrap();
        state.record_block_subsidy(1, 0).unwrap();
        let encoded = state.encode_snapshot().unwrap();
        assert_eq!(encoded.len(), CP0651_SNAPSHOT_BYTES);
        assert_eq!(
            Cp0651FixedSupply::decode_snapshot(&encoded, &NETWORK).unwrap(),
            state
        );
        assert!(Cp0651FixedSupply::decode_snapshot(&encoded, &[0x53; 32]).is_err());
        let mut tampered = encoded;
        tampered[120] ^= 1;
        assert!(Cp0651FixedSupply::decode_snapshot(&tampered, &NETWORK).is_err());
    }
}
