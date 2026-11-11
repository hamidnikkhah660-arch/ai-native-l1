//! CP-0604 versioned founder-controlled supply policy candidate.
//! Genesis credits 7B QZXB to the founder account; consensus mining may issue at most 3B.
//! Earmarks are off-chain accounting labels, never mint buckets.
use crate::qrun_v06_tokenomics_candidate::{QRunV06MiningScheduleCandidate, QZXB_ATOMS_PER_COIN};
use sha2::{Digest, Sha256};
pub type Digest32 = [u8; 32];
pub type AccountId = [u8; 32];
pub const CP0604_MAX_GROSS_ATOMS: u128 = 10_000_000_000u128 * QZXB_ATOMS_PER_COIN;
pub const CP0604_FOUNDER_GENESIS_ATOMS: u128 = 7_000_000_000u128 * QZXB_ATOMS_PER_COIN;
pub const CP0604_MINING_CAP_ATOMS: u128 = 3_000_000_000u128 * QZXB_ATOMS_PER_COIN;
pub const CP0604_SNAPSHOT_BYTES: usize = 232;
const MAGIC: [u8; 4] = *b"Q604";
const VERSION: u16 = 1;
const POLICY_DOMAIN: &[u8] = b"QRUN-V06-CP0604-FOUNDER-7B-MINING-3B-V1\0";
const CHECKSUM_DOMAIN: &[u8] = b"QRUN-V06-CP0604-SNAPSHOT-CHECKSUM-V1\0";
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cp0604Error {
    InvalidNetwork,
    InvalidFounder,
    InvalidHeight,
    InvalidAmount,
    SupplyMismatch { expected: u128, actual: u128 },
    SnapshotMalformed,
    SnapshotChecksum,
    SnapshotNonCanonical,
    Arithmetic,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cp0604FounderControlledSupply {
    network_id: Digest32,
    founder_account: AccountId,
    schedule: QRunV06MiningScheduleCandidate,
    mining_issued_atoms: u128,
    last_mining_height: u64,
}
impl Cp0604FounderControlledSupply {
    pub fn genesis(
        network_id: Digest32,
        founder_account: AccountId,
        schedule: QRunV06MiningScheduleCandidate,
    ) -> Result<Self, Cp0604Error> {
        if network_id == [0; 32] {
            return Err(Cp0604Error::InvalidNetwork);
        }
        if founder_account == [0; 32] {
            return Err(Cp0604Error::InvalidFounder);
        }
        schedule
            .validate()
            .map_err(|_| Cp0604Error::InvalidAmount)?;
        Ok(Self {
            network_id,
            founder_account,
            schedule,
            mining_issued_atoms: 0,
            last_mining_height: 0,
        })
    }
    pub fn network_id(&self) -> Digest32 {
        self.network_id
    }
    pub fn founder_account(&self) -> AccountId {
        self.founder_account
    }
    pub fn founder_genesis_atoms(&self) -> u128 {
        CP0604_FOUNDER_GENESIS_ATOMS
    }
    pub fn mining_issued_atoms(&self) -> u128 {
        self.mining_issued_atoms
    }
    pub fn last_mining_height(&self) -> u64 {
        self.last_mining_height
    }
    pub fn gross_issued_atoms(&self) -> Result<u128, Cp0604Error> {
        CP0604_FOUNDER_GENESIS_ATOMS
            .checked_add(self.mining_issued_atoms)
            .ok_or(Cp0604Error::Arithmetic)
    }
    pub fn expected_mining_reward_atoms(&self, height: u64) -> Result<u128, Cp0604Error> {
        if height == 0
            || height
                != self
                    .last_mining_height
                    .checked_add(1)
                    .ok_or(Cp0604Error::Arithmetic)?
        {
            return Err(Cp0604Error::InvalidHeight);
        }
        let remaining = CP0604_MINING_CAP_ATOMS
            .checked_sub(self.mining_issued_atoms)
            .ok_or(Cp0604Error::Arithmetic)?;
        let scheduled = self
            .schedule
            .reward_for_height(height)
            .map_err(|_| Cp0604Error::InvalidHeight)?;
        Ok(scheduled.min(remaining))
    }
    /// Call only in the canonical block transition after consensus has selected the producer.
    pub fn record_mining_reward(
        &mut self,
        height: u64,
        amount_atoms: u128,
    ) -> Result<(), Cp0604Error> {
        let expected = self.expected_mining_reward_atoms(height)?;
        if amount_atoms != expected {
            return Err(Cp0604Error::InvalidAmount);
        }
        let next = self
            .mining_issued_atoms
            .checked_add(amount_atoms)
            .ok_or(Cp0604Error::Arithmetic)?;
        if next > CP0604_MINING_CAP_ATOMS
            || CP0604_FOUNDER_GENESIS_ATOMS
                .checked_add(next)
                .ok_or(Cp0604Error::Arithmetic)?
                > CP0604_MAX_GROSS_ATOMS
        {
            return Err(Cp0604Error::InvalidAmount);
        }
        self.mining_issued_atoms = next;
        self.last_mining_height = height;
        Ok(())
    }
    /// Native transfers only redistribute balances; total Ledger supply must match issuance.
    pub fn validate_ledger_supply(&self, ledger_total_atoms: u128) -> Result<(), Cp0604Error> {
        let expected = self.gross_issued_atoms()?;
        if ledger_total_atoms != expected {
            return Err(Cp0604Error::SupplyMismatch {
                expected,
                actual: ledger_total_atoms,
            });
        }
        Ok(())
    }
    pub fn policy_fingerprint(&self) -> Digest32 {
        let mut h = Sha256::new();
        h.update(POLICY_DOMAIN);
        h.update(CP0604_MAX_GROSS_ATOMS.to_be_bytes());
        h.update(CP0604_FOUNDER_GENESIS_ATOMS.to_be_bytes());
        h.update(CP0604_MINING_CAP_ATOMS.to_be_bytes());
        h.update(self.schedule.initial_subsidy_atoms.to_be_bytes());
        h.update(self.schedule.blocks_per_halving.to_be_bytes());
        h.finalize().into()
    }
    pub fn state_root(&self) -> Digest32 {
        let mut h = Sha256::new();
        h.update(b"QRUN-V06-CP0604-STATE-ROOT-V1\0");
        h.update(self.network_id);
        h.update(self.founder_account);
        h.update(self.policy_fingerprint());
        h.update(self.mining_issued_atoms.to_be_bytes());
        h.update(self.last_mining_height.to_be_bytes());
        h.finalize().into()
    }
    pub fn encode_snapshot(&self) -> [u8; CP0604_SNAPSHOT_BYTES] {
        let mut out = Vec::with_capacity(CP0604_SNAPSHOT_BYTES);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&self.network_id);
        out.extend_from_slice(&self.founder_account);
        out.extend_from_slice(&CP0604_MAX_GROSS_ATOMS.to_be_bytes());
        out.extend_from_slice(&CP0604_FOUNDER_GENESIS_ATOMS.to_be_bytes());
        out.extend_from_slice(&CP0604_MINING_CAP_ATOMS.to_be_bytes());
        out.extend_from_slice(&self.schedule.initial_subsidy_atoms.to_be_bytes());
        out.extend_from_slice(&self.schedule.blocks_per_halving.to_be_bytes());
        out.extend_from_slice(&self.mining_issued_atoms.to_be_bytes());
        out.extend_from_slice(&self.last_mining_height.to_be_bytes());
        out.extend_from_slice(&self.policy_fingerprint());
        let mut h = Sha256::new();
        h.update(CHECKSUM_DOMAIN);
        h.update(&out);
        out.extend_from_slice(&h.finalize());
        let mut bytes = [0u8; CP0604_SNAPSHOT_BYTES];
        bytes.copy_from_slice(&out);
        bytes
    }
    pub fn decode_snapshot(bytes: &[u8], expected_network: &Digest32) -> Result<Self, Cp0604Error> {
        if bytes.len() != CP0604_SNAPSHOT_BYTES {
            return Err(Cp0604Error::SnapshotMalformed);
        }
        let payload = &bytes[..CP0604_SNAPSHOT_BYTES - 32];
        let mut h = Sha256::new();
        h.update(CHECKSUM_DOMAIN);
        h.update(payload);
        if h.finalize().as_slice() != &bytes[CP0604_SNAPSHOT_BYTES - 32..] {
            return Err(Cp0604Error::SnapshotChecksum);
        }
        let mut c = 0usize;
        fn take<const N: usize>(b: &[u8], c: &mut usize) -> Result<[u8; N], Cp0604Error> {
            let e = c.checked_add(N).ok_or(Cp0604Error::SnapshotMalformed)?;
            let s = b.get(*c..e).ok_or(Cp0604Error::SnapshotMalformed)?;
            *c = e;
            let mut a = [0u8; N];
            a.copy_from_slice(s);
            Ok(a)
        }
        let magic = take::<4>(payload, &mut c)?;
        let version = u16::from_be_bytes(take::<2>(payload, &mut c)?);
        let reserved = u16::from_be_bytes(take::<2>(payload, &mut c)?);
        let network = take::<32>(payload, &mut c)?;
        let founder = take::<32>(payload, &mut c)?;
        let max = u128::from_be_bytes(take::<16>(payload, &mut c)?);
        let founder_amount = u128::from_be_bytes(take::<16>(payload, &mut c)?);
        let mining_cap = u128::from_be_bytes(take::<16>(payload, &mut c)?);
        let initial = u128::from_be_bytes(take::<16>(payload, &mut c)?);
        let halving = u64::from_be_bytes(take::<8>(payload, &mut c)?);
        let issued = u128::from_be_bytes(take::<16>(payload, &mut c)?);
        let height = u64::from_be_bytes(take::<8>(payload, &mut c)?);
        let fingerprint = take::<32>(payload, &mut c)?;
        if magic != MAGIC
            || version != VERSION
            || reserved != 0
            || network != *expected_network
            || max != CP0604_MAX_GROSS_ATOMS
            || founder_amount != CP0604_FOUNDER_GENESIS_ATOMS
            || mining_cap != CP0604_MINING_CAP_ATOMS
            || c != payload.len()
        {
            return Err(Cp0604Error::SnapshotNonCanonical);
        }
        let schedule = QRunV06MiningScheduleCandidate::new(initial, halving)
            .map_err(|_| Cp0604Error::SnapshotNonCanonical)?;
        let value = Self {
            network_id: network,
            founder_account: founder,
            schedule,
            mining_issued_atoms: issued,
            last_mining_height: height,
        };
        if value.policy_fingerprint() != fingerprint
            || issued > CP0604_MINING_CAP_ATOMS
            || CP0604_FOUNDER_GENESIS_ATOMS + issued > CP0604_MAX_GROSS_ATOMS
            || (height == 0) != (issued == 0)
            || value.encode_snapshot().as_slice() != bytes
        {
            return Err(Cp0604Error::SnapshotNonCanonical);
        }
        Ok(value)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    const NETWORK: Digest32 = [0x61; 32];
    const FOUNDER: AccountId = [0x62; 32];
    fn state() -> Cp0604FounderControlledSupply {
        Cp0604FounderControlledSupply::genesis(
            NETWORK,
            FOUNDER,
            QRunV06MiningScheduleCandidate::cp0422_research_candidate(),
        )
        .unwrap()
    }
    #[test]
    fn genesis_commits_seven_billion_founder_and_three_billion_mining_cap() {
        let s = state();
        assert_eq!(s.founder_genesis_atoms(), CP0604_FOUNDER_GENESIS_ATOMS);
        assert_eq!(
            s.gross_issued_atoms().unwrap(),
            CP0604_FOUNDER_GENESIS_ATOMS
        );
        assert_eq!(
            CP0604_FOUNDER_GENESIS_ATOMS + CP0604_MINING_CAP_ATOMS,
            CP0604_MAX_GROSS_ATOMS
        )
    }
    #[test]
    fn mining_is_sequential_and_cannot_exceed_three_billion() {
        let mut s = state();
        let reward = s.expected_mining_reward_atoms(1).unwrap();
        assert!(s.record_mining_reward(2, reward).is_err());
        s.record_mining_reward(1, reward).unwrap();
        assert_eq!(s.mining_issued_atoms(), reward);
        assert!(s.record_mining_reward(1, reward).is_err())
    }
    #[test]
    fn zero_reward_heights_remain_sequential_after_schedule_exhaustion() {
        let mut s = Cp0604FounderControlledSupply::genesis(
            NETWORK,
            FOUNDER,
            QRunV06MiningScheduleCandidate::new(1, 1).unwrap(),
        )
        .unwrap();
        s.record_mining_reward(1, 1).unwrap();
        assert_eq!(s.expected_mining_reward_atoms(2).unwrap(), 0);
        s.record_mining_reward(2, 0).unwrap();
        assert_eq!(s.last_mining_height(), 2);
        assert_eq!(s.mining_issued_atoms(), 1);
    }

    #[test]
    fn transfers_do_not_change_issuance_accounting() {
        let s = state();
        assert!(s
            .validate_ledger_supply(CP0604_FOUNDER_GENESIS_ATOMS)
            .is_ok());
        assert!(s
            .validate_ledger_supply(CP0604_FOUNDER_GENESIS_ATOMS + 1)
            .is_err())
    }
    #[test]
    fn snapshot_roundtrip_and_network_binding() {
        let s = state();
        let b = s.encode_snapshot();
        assert_eq!(b.len(), CP0604_SNAPSHOT_BYTES);
        assert_eq!(
            Cp0604FounderControlledSupply::decode_snapshot(&b, &NETWORK).unwrap(),
            s
        );
        assert!(Cp0604FounderControlledSupply::decode_snapshot(&b, &[0x63; 32]).is_err())
    }
    #[test]
    fn snapshot_detects_tampering() {
        let s = state();
        let mut b = s.encode_snapshot();
        b[80] ^= 1;
        assert!(Cp0604FounderControlledSupply::decode_snapshot(&b, &NETWORK).is_err())
    }
}
