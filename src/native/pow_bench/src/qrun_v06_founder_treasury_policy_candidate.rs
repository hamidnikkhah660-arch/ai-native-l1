//! CP-0603 founder-controlled Treasury accounting candidate.
//! Separate candidate state; not yet wired into canonical QFB6 execution.
use sha2::{Digest, Sha256};
pub type AccountId = [u8; 32];
pub type Digest32 = [u8; 32];
pub const QZXB_ATOMS_PER_COIN: u128 = 100_000_000;
pub const MAX_SUPPLY_ATOMS: u128 = 10_000_000_000 * QZXB_ATOMS_PER_COIN;
pub const FOUNDER_DIRECT_GENESIS_ATOMS: u128 = 1_000_000_000 * QZXB_ATOMS_PER_COIN;
pub const FOUNDER_TREASURY_GENESIS_ATOMS: u128 = 6_000_000_000 * QZXB_ATOMS_PER_COIN;
pub const FOUNDER_TOTAL_GENESIS_ATOMS: u128 =
    FOUNDER_DIRECT_GENESIS_ATOMS + FOUNDER_TREASURY_GENESIS_ATOMS;
pub const MINING_CEILING_ATOMS: u128 = 3_000_000_000 * QZXB_ATOMS_PER_COIN;
pub const EACH_TREASURY_PRIORITY_ATOMS: u128 = 1_000_000_000 * QZXB_ATOMS_PER_COIN;
const ROOT_DOMAIN: &[u8] = b"QZXB-CP0603-FOUNDER-TREASURY-STATE-V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FounderTreasuryPriority {
    Community = 0,
    ExchangeAndLiquidity = 1,
    Marketing = 2,
    DevelopersAndSecurity = 3,
    StrategicSupporters = 4,
    ConditionalBurn = 5,
}
impl FounderTreasuryPriority {
    pub const ALL: [Self; 6] = [
        Self::Community,
        Self::ExchangeAndLiquidity,
        Self::Marketing,
        Self::DevelopersAndSecurity,
        Self::StrategicSupporters,
        Self::ConditionalBurn,
    ];
    pub const fn ceiling_atoms(self) -> u128 {
        EACH_TREASURY_PRIORITY_ATOMS
    }
    const fn index(self) -> usize {
        self as usize
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreasuryError {
    InvalidFounder,
    InvalidRecipient,
    UnauthorizedOwner,
    InvalidAmount,
    InvalidNonce,
    Replay,
    PriorityCeilingExceeded,
    FounderBalanceInsufficient,
    ArithmeticOverflow,
    SupplyArithmeticMismatch,
}

/// The canonical executor MUST verify the founder's hybrid signature before invoking transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FounderTreasuryState {
    founder: AccountId,
    founder_balance_atoms: u128,
    released_by_priority_atoms: [u128; 6],
    burned_atoms: u128,
    owner_nonce: u64,
    last_operation_id: Digest32,
}
impl FounderTreasuryState {
    pub fn genesis(founder: AccountId) -> Result<Self, TreasuryError> {
        if founder == [0; 32] {
            return Err(TreasuryError::InvalidFounder);
        }
        validate_policy_arithmetic().map_err(|_| TreasuryError::SupplyArithmeticMismatch)?;
        Ok(Self {
            founder,
            founder_balance_atoms: FOUNDER_TOTAL_GENESIS_ATOMS,
            released_by_priority_atoms: [0; 6],
            burned_atoms: 0,
            owner_nonce: 0,
            last_operation_id: [0; 32],
        })
    }
    pub fn founder(&self) -> AccountId {
        self.founder
    }
    pub fn founder_balance_atoms(&self) -> u128 {
        self.founder_balance_atoms
    }
    pub fn released_by_priority_atoms(&self, p: FounderTreasuryPriority) -> u128 {
        self.released_by_priority_atoms[p.index()]
    }
    pub fn burned_atoms(&self) -> u128 {
        self.burned_atoms
    }
    pub fn owner_nonce(&self) -> u64 {
        self.owner_nonce
    }
    /// Transfer already-issued founder coins; never increases gross issuance.
    pub fn authorize_release(
        &mut self,
        signer: AccountId,
        recipient: AccountId,
        priority: FounderTreasuryPriority,
        amount: u128,
        nonce: u64,
        operation_id: Digest32,
    ) -> Result<(), TreasuryError> {
        if signer != self.founder {
            return Err(TreasuryError::UnauthorizedOwner);
        }
        if recipient == [0; 32] {
            return Err(TreasuryError::InvalidRecipient);
        }
        self.check_operation(amount, nonce, operation_id)?;
        if priority == FounderTreasuryPriority::ConditionalBurn {
            return Err(TreasuryError::PriorityCeilingExceeded);
        }
        let i = priority.index();
        let released = self.released_by_priority_atoms[i]
            .checked_add(amount)
            .ok_or(TreasuryError::ArithmeticOverflow)?;
        if released > priority.ceiling_atoms() {
            return Err(TreasuryError::PriorityCeilingExceeded);
        }
        let balance = self
            .founder_balance_atoms
            .checked_sub(amount)
            .ok_or(TreasuryError::FounderBalanceInsufficient)?;
        self.released_by_priority_atoms[i] = released;
        self.founder_balance_atoms = balance;
        self.commit_operation(nonce, operation_id);
        Ok(())
    }
    /// Irreversibly burn founder-held coins within the founder-controlled 1B burn earmark.
    pub fn authorize_burn(
        &mut self,
        signer: AccountId,
        amount: u128,
        nonce: u64,
        operation_id: Digest32,
    ) -> Result<(), TreasuryError> {
        if signer != self.founder {
            return Err(TreasuryError::UnauthorizedOwner);
        }
        self.check_operation(amount, nonce, operation_id)?;
        let burned = self
            .burned_atoms
            .checked_add(amount)
            .ok_or(TreasuryError::ArithmeticOverflow)?;
        if burned > EACH_TREASURY_PRIORITY_ATOMS {
            return Err(TreasuryError::PriorityCeilingExceeded);
        }
        let balance = self
            .founder_balance_atoms
            .checked_sub(amount)
            .ok_or(TreasuryError::FounderBalanceInsufficient)?;
        self.burned_atoms = burned;
        self.founder_balance_atoms = balance;
        self.released_by_priority_atoms[FounderTreasuryPriority::ConditionalBurn.index()] = burned;
        self.commit_operation(nonce, operation_id);
        Ok(())
    }
    fn check_operation(&self, amount: u128, nonce: u64, id: Digest32) -> Result<(), TreasuryError> {
        if amount == 0 {
            return Err(TreasuryError::InvalidAmount);
        }
        if id == [0; 32] || id == self.last_operation_id {
            return Err(TreasuryError::Replay);
        }
        if nonce
            != self
                .owner_nonce
                .checked_add(1)
                .ok_or(TreasuryError::ArithmeticOverflow)?
        {
            return Err(TreasuryError::InvalidNonce);
        }
        Ok(())
    }
    fn commit_operation(&mut self, nonce: u64, id: Digest32) {
        self.owner_nonce = nonce;
        self.last_operation_id = id;
    }
    /// Founder balance + recipient transfers + burned coins = original 7B.
    pub fn founder_distribution_accounted_atoms(&self) -> Result<u128, TreasuryError> {
        let released = self
            .released_by_priority_atoms
            .iter()
            .take(5)
            .try_fold(0u128, |s, v| {
                s.checked_add(*v).ok_or(TreasuryError::ArithmeticOverflow)
            })?;
        self.founder_balance_atoms
            .checked_add(released)
            .and_then(|v| v.checked_add(self.burned_atoms))
            .ok_or(TreasuryError::ArithmeticOverflow)
    }
    pub fn state_root(&self) -> Digest32 {
        let mut h = Sha256::new();
        h.update(ROOT_DOMAIN);
        h.update(self.founder);
        h.update(self.founder_balance_atoms.to_be_bytes());
        for v in self.released_by_priority_atoms {
            h.update(v.to_be_bytes())
        }
        h.update(self.burned_atoms.to_be_bytes());
        h.update(self.owner_nonce.to_be_bytes());
        h.update(self.last_operation_id);
        h.finalize().into()
    }
}
pub fn validate_policy_arithmetic() -> Result<(), &'static str> {
    if EACH_TREASURY_PRIORITY_ATOMS
        .checked_mul(6)
        .ok_or("overflow")?
        != FOUNDER_TREASURY_GENESIS_ATOMS
    {
        return Err("six earmarks != 6B");
    }
    if FOUNDER_TOTAL_GENESIS_ATOMS
        .checked_add(MINING_CEILING_ATOMS)
        .ok_or("overflow")?
        != MAX_SUPPLY_ATOMS
    {
        return Err("7B founder + 3B mining != 10B");
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn state() -> FounderTreasuryState {
        FounderTreasuryState::genesis([7; 32]).unwrap()
    }
    #[test]
    fn genesis_is_seven_billion_in_one_account() {
        let s = state();
        assert_eq!(
            s.founder_balance_atoms(),
            7_000_000_000 * QZXB_ATOMS_PER_COIN
        );
        assert_eq!(
            s.founder_distribution_accounted_atoms().unwrap(),
            FOUNDER_TOTAL_GENESIS_ATOMS
        );
        validate_policy_arithmetic().unwrap();
    }
    #[test]
    fn release_is_transfer_not_mint_and_owner_gated() {
        let mut s = state();
        assert_eq!(
            s.authorize_release(
                [8; 32],
                [9; 32],
                FounderTreasuryPriority::Community,
                10,
                1,
                [1; 32]
            ),
            Err(TreasuryError::UnauthorizedOwner)
        );
        let b = s.founder_balance_atoms();
        s.authorize_release(
            [7; 32],
            [9; 32],
            FounderTreasuryPriority::Community,
            10,
            1,
            [1; 32],
        )
        .unwrap();
        assert_eq!(s.founder_balance_atoms(), b - 10);
        assert_eq!(
            s.founder_distribution_accounted_atoms().unwrap(),
            FOUNDER_TOTAL_GENESIS_ATOMS
        );
        assert_eq!(
            s.authorize_release(
                [7; 32],
                [9; 32],
                FounderTreasuryPriority::Community,
                10,
                1,
                [1; 32]
            ),
            Err(TreasuryError::Replay)
        );
    }
    #[test]
    fn priority_ceiling_is_enforced() {
        let mut s = state();
        assert_eq!(
            s.authorize_release(
                [7; 32],
                [9; 32],
                FounderTreasuryPriority::Community,
                EACH_TREASURY_PRIORITY_ATOMS + 1,
                1,
                [1; 32]
            ),
            Err(TreasuryError::PriorityCeilingExceeded)
        );
    }
    #[test]
    fn burn_is_owner_directed_and_reduces_founder_balance() {
        let mut s = state();
        let b = s.founder_balance_atoms();
        s.authorize_burn([7; 32], 100, 1, [2; 32]).unwrap();
        assert_eq!(s.founder_balance_atoms(), b - 100);
        assert_eq!(s.burned_atoms(), 100);
        assert_eq!(
            s.founder_distribution_accounted_atoms().unwrap(),
            FOUNDER_TOTAL_GENESIS_ATOMS
        );
    }
    #[test]
    fn burn_cannot_exceed_one_billion() {
        let mut s = state();
        assert_eq!(
            s.authorize_burn([7; 32], EACH_TREASURY_PRIORITY_ATOMS + 1, 1, [2; 32]),
            Err(TreasuryError::PriorityCeilingExceeded)
        );
    }
}
