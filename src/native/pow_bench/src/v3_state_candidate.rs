//! CP-0217-S3S: isolated deterministic V3 state-root and STV3 snapshot candidate.
//! Not connected to canonical consensus, persistence, issuance or governance transitions.
use sha2::{Digest, Sha256};

pub const STV3_MAX_BYTES: usize = 8_388_608;
pub const ACCOUNT_RECORD_LEN: usize = 48;
pub const PROPOSAL_RECORD_LEN: usize = 170;
pub const MAX_ACCOUNTS: usize = 100_000;
pub const MAX_PENDING_PROPOSALS: usize = 4_096;
pub const TIMELOCK_BLOCKS: u64 = 20_160;
pub const EXECUTION_WINDOW_BLOCKS: u64 = 86_400;
const STATE_PREFIX: &[u8] = b"AIN1-STATE-V3\0";
const ROOT_DOMAIN: &[u8] = b"AIN1-STATE-ROOT-V3\0";
const CHECK_DOMAIN: &[u8] = b"AIN1-STATE-SNAPSHOT-CHECK-V3\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateCodecError {
    Incomplete,
    TrailingBytes,
    BadMagic,
    Version(u16),
    WrongNetwork,
    WrongManifest,
    WrongGovernanceConfig,
    BadChecksum,
    StateRootMismatch,
    Invalid(&'static str),
    Length(&'static str),
    Limit(&'static str),
    Overflow,
}
fn zero(b: &[u8]) -> bool {
    b.iter().all(|x| *x == 0)
}
fn hash(d: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(d);
    h.update(b);
    h.finalize().into()
}
fn take<'a>(b: &'a [u8], p: &mut usize, n: usize) -> Result<&'a [u8], StateCodecError> {
    let e = (*p).checked_add(n).ok_or(StateCodecError::Overflow)?;
    let x = b.get(*p..e).ok_or(StateCodecError::Incomplete)?;
    *p = e;
    Ok(x)
}
fn r16(b: &[u8], p: &mut usize) -> Result<u16, StateCodecError> {
    Ok(u16::from_be_bytes(take(b, p, 2)?.try_into().unwrap()))
}
fn r32(b: &[u8], p: &mut usize) -> Result<u32, StateCodecError> {
    Ok(u32::from_be_bytes(take(b, p, 4)?.try_into().unwrap()))
}
fn r64(b: &[u8], p: &mut usize) -> Result<u64, StateCodecError> {
    Ok(u64::from_be_bytes(take(b, p, 8)?.try_into().unwrap()))
}
fn rbytes32(b: &[u8], p: &mut usize) -> Result<[u8; 32], StateCodecError> {
    Ok(take(b, p, 32)?.try_into().unwrap())
}
fn founder_due_atoms(height: u64, budget: u64) -> Result<u64, StateCodecError> {
    if height == 0 {
        return Ok(0);
    }
    let index = height - 1;
    if index < 1_138_800 {
        return Ok(0);
    }
    let periods = ((index - 1_051_200) / 87_600).min(48);
    let due = u128::from(budget)
        .checked_mul(u128::from(periods))
        .ok_or(StateCodecError::Overflow)?
        / 48;
    u64::try_from(due).map_err(|_| StateCodecError::Overflow)
}
fn sum(xs: impl IntoIterator<Item = u64>) -> Result<u128, StateCodecError> {
    xs.into_iter().try_fold(0u128, |a, x| {
        a.checked_add(u128::from(x))
            .ok_or(StateCodecError::Overflow)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateLimits {
    pub total_supply_atoms: u64,
    pub miner_budget_atoms: u64,
    pub founder_budget_atoms: u64,
    pub public_goods_budgets_atoms: [u64; 6],
    pub max_accounts: usize,
    pub max_pending_proposals: usize,
    pub max_snapshot_bytes: usize,
}
impl Default for StateLimits {
    fn default() -> Self {
        Self {
            total_supply_atoms: 1_000_000_000_000_000_000,
            miner_budget_atoms: 300_000_000_000_000_000,
            founder_budget_atoms: 400_000_000_000_000_000,
            public_goods_budgets_atoms: [
                30_000_000_000_000_000,
                90_000_000_000_000_000,
                60_000_000_000_000_000,
                30_000_000_000_000_000,
                30_000_000_000_000_000,
                60_000_000_000_000_000,
            ],
            max_accounts: MAX_ACCOUNTS,
            max_pending_proposals: MAX_PENDING_PROPOSALS,
            max_snapshot_bytes: STV3_MAX_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRecordV3 {
    pub account_id: [u8; 32],
    pub balance_atoms: u64,
    pub nonce: u64,
}
impl AccountRecordV3 {
    fn put(&self, v: &mut Vec<u8>) {
        v.extend_from_slice(&self.account_id);
        v.extend_from_slice(&self.balance_atoms.to_be_bytes());
        v.extend_from_slice(&self.nonce.to_be_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingProposalV3 {
    pub proposal_id: [u8; 32],
    pub proposer_signer_id: [u8; 32],
    pub proposer_nonce: u64,
    pub bucket_id: u8,
    pub recipient_id: [u8; 32],
    pub amount_atoms: u64,
    pub rationale_hash: [u8; 32],
    pub submitted_height: u64,
    pub not_before_height: u64,
    pub expires_height: u64,
    pub approval_bitmap: u8,
}
impl PendingProposalV3 {
    pub fn validate(&self) -> Result<(), StateCodecError> {
        if zero(&self.proposal_id) || zero(&self.proposer_signer_id) || zero(&self.recipient_id) {
            return Err(StateCodecError::Invalid(
                "zero proposal/proposer/recipient id",
            ));
        }
        if self.proposer_nonce == 0 || !(1..=6).contains(&self.bucket_id) || self.amount_atoms == 0
        {
            return Err(StateCodecError::Invalid("proposal nonce/bucket/amount"));
        }
        if self.approval_bitmap == 0 || self.approval_bitmap & !0x7f != 0 {
            return Err(StateCodecError::Invalid("proposal approval bitmap"));
        }
        let n = self
            .submitted_height
            .checked_add(TIMELOCK_BLOCKS)
            .ok_or(StateCodecError::Overflow)?;
        let e = n
            .checked_add(EXECUTION_WINDOW_BLOCKS)
            .ok_or(StateCodecError::Overflow)?;
        if self.not_before_height != n || self.expires_height != e {
            return Err(StateCodecError::Invalid("proposal timelock/expiry"));
        }
        Ok(())
    }
    fn put(&self, v: &mut Vec<u8>) {
        v.extend_from_slice(&self.proposal_id);
        v.extend_from_slice(&self.proposer_signer_id);
        v.extend_from_slice(&self.proposer_nonce.to_be_bytes());
        v.push(self.bucket_id);
        v.extend_from_slice(&self.recipient_id);
        v.extend_from_slice(&self.amount_atoms.to_be_bytes());
        v.extend_from_slice(&self.rationale_hash);
        v.extend_from_slice(&self.submitted_height.to_be_bytes());
        v.extend_from_slice(&self.not_before_height.to_be_bytes());
        v.extend_from_slice(&self.expires_height.to_be_bytes());
        v.push(self.approval_bitmap)
    }
    fn get(b: &[u8], p: &mut usize) -> Result<Self, StateCodecError> {
        let x = Self {
            proposal_id: rbytes32(b, p)?,
            proposer_signer_id: rbytes32(b, p)?,
            proposer_nonce: r64(b, p)?,
            bucket_id: take(b, p, 1)?[0],
            recipient_id: rbytes32(b, p)?,
            amount_atoms: r64(b, p)?,
            rationale_hash: rbytes32(b, p)?,
            submitted_height: r64(b, p)?,
            not_before_height: r64(b, p)?,
            expires_height: r64(b, p)?,
            approval_bitmap: take(b, p, 1)?[0],
        };
        x.validate()?;
        Ok(x)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateV3 {
    pub network_id: [u8; 32],
    pub height: u64,
    pub last_timestamp: u64,
    pub manifest_id: [u8; 32],
    pub governance_config_hash: [u8; 32],
    pub total_issued_atoms: u64,
    pub miner_issued_atoms: u64,
    pub founder_issued_atoms: u64,
    pub public_goods_issued_atoms: [u64; 6],
    pub total_burned_atoms: u64,
    /// The seven values correspond to the manifest-bound roster sorted by signer ID.
    pub proposer_nonce_highwater: [u64; 7],
    pub accounts: Vec<AccountRecordV3>,
    pub pending_proposals: Vec<PendingProposalV3>,
}
impl StateV3 {
    pub fn validate(&self, l: &StateLimits) -> Result<(), StateCodecError> {
        if zero(&self.network_id) || zero(&self.manifest_id) || zero(&self.governance_config_hash) {
            return Err(StateCodecError::Invalid(
                "zero network/manifest/governance hash",
            ));
        }
        if (self.height == 0 && self.last_timestamp != 0)
            || (self.height > 0 && self.last_timestamp == 0)
        {
            return Err(StateCodecError::Invalid("height/timestamp consistency"));
        }
        if self.height == 0 {
            let any_bucket = self.public_goods_issued_atoms.iter().any(|x| *x != 0);
            if self.last_timestamp != 0
                || self.total_issued_atoms != 0
                || self.miner_issued_atoms != 0
                || self.founder_issued_atoms != 0
                || any_bucket
                || self.total_burned_atoms != 0
                || self.proposer_nonce_highwater.iter().any(|x| *x != 0)
                || !self.accounts.is_empty()
                || !self.pending_proposals.is_empty()
            {
                return Err(StateCodecError::Invalid(
                    "Genesis state must have zero counters and no records",
                ));
            }
        }
        if self.accounts.len() > l.max_accounts.min(MAX_ACCOUNTS) {
            return Err(StateCodecError::Limit("accounts"));
        }
        if self.pending_proposals.len() > l.max_pending_proposals.min(MAX_PENDING_PROPOSALS) {
            return Err(StateCodecError::Limit("pending proposals"));
        }
        let issued = sum([self.miner_issued_atoms, self.founder_issued_atoms]
            .into_iter()
            .chain(self.public_goods_issued_atoms))?;
        if issued != u128::from(self.total_issued_atoms) {
            return Err(StateCodecError::Invalid("issuance counter sum"));
        }
        if self.total_issued_atoms > l.total_supply_atoms
            || self.miner_issued_atoms > l.miner_budget_atoms
            || self.founder_issued_atoms > l.founder_budget_atoms
        {
            return Err(StateCodecError::Limit("total/miner/founder budget"));
        }
        for i in 0..6 {
            if self.public_goods_issued_atoms[i] > l.public_goods_budgets_atoms[i] {
                return Err(StateCodecError::Limit("public-goods bucket budget"));
            }
        }
        if self.founder_issued_atoms > founder_due_atoms(self.height, l.founder_budget_atoms)? {
            return Err(StateCodecError::Invalid(
                "founder issuance exceeds height schedule",
            ));
        }
        if self.total_burned_atoms > self.total_issued_atoms {
            return Err(StateCodecError::Invalid("burn exceeds issued"));
        }
        if sum(self.accounts.iter().map(|a| a.balance_atoms))?
            != u128::from(self.total_issued_atoms - self.total_burned_atoms)
        {
            return Err(StateCodecError::Invalid("account-balance conservation"));
        }
        for (i, a) in self.accounts.iter().enumerate() {
            if zero(&a.account_id) {
                return Err(StateCodecError::Invalid("zero account id"));
            }
            if i > 0 && self.accounts[i - 1].account_id >= a.account_id {
                return Err(StateCodecError::Invalid(
                    "account IDs not strictly ascending",
                ));
            }
        }
        for (i, p) in self.pending_proposals.iter().enumerate() {
            p.validate()?;
            if p.expires_height < self.height {
                return Err(StateCodecError::Invalid(
                    "expired proposal retained in state",
                ));
            }
            if i > 0 && self.pending_proposals[i - 1].proposal_id >= p.proposal_id {
                return Err(StateCodecError::Invalid(
                    "proposal IDs not strictly ascending",
                ));
            }
        }
        Ok(())
    }
    pub fn canonical_state_bytes(&self, l: &StateLimits) -> Result<Vec<u8>, StateCodecError> {
        self.validate(l)?;
        let ab = self
            .accounts
            .len()
            .checked_mul(48)
            .ok_or(StateCodecError::Overflow)?;
        let pb = self
            .pending_proposals
            .len()
            .checked_mul(170)
            .ok_or(StateCodecError::Overflow)?;
        let n = STATE_PREFIX
            .len()
            .checked_add(32 + 8 + 8 + 32 + 32 + 80 + 56 + 4 + ab + 2 + pb)
            .ok_or(StateCodecError::Overflow)?;
        let mut v = Vec::with_capacity(n);
        v.extend_from_slice(STATE_PREFIX);
        v.extend_from_slice(&self.network_id);
        v.extend_from_slice(&self.height.to_be_bytes());
        v.extend_from_slice(&self.last_timestamp.to_be_bytes());
        v.extend_from_slice(&self.manifest_id);
        v.extend_from_slice(&self.governance_config_hash);
        v.extend_from_slice(&self.total_issued_atoms.to_be_bytes());
        v.extend_from_slice(&self.miner_issued_atoms.to_be_bytes());
        v.extend_from_slice(&self.founder_issued_atoms.to_be_bytes());
        for x in self.public_goods_issued_atoms {
            v.extend_from_slice(&x.to_be_bytes())
        }
        v.extend_from_slice(&self.total_burned_atoms.to_be_bytes());
        for x in self.proposer_nonce_highwater {
            v.extend_from_slice(&x.to_be_bytes())
        }
        v.extend_from_slice(&(self.accounts.len() as u32).to_be_bytes());
        for a in &self.accounts {
            a.put(&mut v)
        }
        v.extend_from_slice(&(self.pending_proposals.len() as u16).to_be_bytes());
        for p in &self.pending_proposals {
            p.put(&mut v)
        }
        debug_assert_eq!(v.len(), n);
        Ok(v)
    }
    pub fn state_root(&self, l: &StateLimits) -> Result<[u8; 32], StateCodecError> {
        Ok(hash(ROOT_DOMAIN, &self.canonical_state_bytes(l)?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateSnapshotV3 {
    pub state: StateV3,
    pub body_tip_id: [u8; 32],
    pub consensus_tip_digest: [u8; 32],
}
impl StateSnapshotV3 {
    pub fn encode(&self, l: &StateLimits) -> Result<Vec<u8>, StateCodecError> {
        self.state.validate(l)?;
        let ab = self
            .state
            .accounts
            .len()
            .checked_mul(48)
            .ok_or(StateCodecError::Overflow)?;
        let pb = self
            .state
            .pending_proposals
            .len()
            .checked_mul(170)
            .ok_or(StateCodecError::Overflow)?;
        let n = 322usize
            .checked_add(ab)
            .and_then(|x| x.checked_add(2))
            .and_then(|x| x.checked_add(pb))
            .and_then(|x| x.checked_add(32))
            .ok_or(StateCodecError::Overflow)?;
        if n > l.max_snapshot_bytes.min(STV3_MAX_BYTES) {
            return Err(StateCodecError::Limit("STV3 bytes"));
        }
        let s = &self.state;
        let mut v = Vec::with_capacity(n);
        v.extend_from_slice(b"STV3");
        v.extend_from_slice(&3u16.to_be_bytes());
        v.extend_from_slice(&s.network_id);
        v.extend_from_slice(&s.height.to_be_bytes());
        v.extend_from_slice(&s.last_timestamp.to_be_bytes());
        v.extend_from_slice(&self.body_tip_id);
        v.extend_from_slice(&self.consensus_tip_digest);
        v.extend_from_slice(&s.manifest_id);
        v.extend_from_slice(&s.governance_config_hash);
        v.extend_from_slice(&s.total_issued_atoms.to_be_bytes());
        v.extend_from_slice(&s.miner_issued_atoms.to_be_bytes());
        v.extend_from_slice(&s.founder_issued_atoms.to_be_bytes());
        for x in s.public_goods_issued_atoms {
            v.extend_from_slice(&x.to_be_bytes())
        }
        v.extend_from_slice(&s.total_burned_atoms.to_be_bytes());
        for x in s.proposer_nonce_highwater {
            v.extend_from_slice(&x.to_be_bytes())
        }
        v.extend_from_slice(&(s.accounts.len() as u32).to_be_bytes());
        for a in &s.accounts {
            a.put(&mut v)
        }
        v.extend_from_slice(&(s.pending_proposals.len() as u16).to_be_bytes());
        for p in &s.pending_proposals {
            p.put(&mut v)
        }
        let c = hash(CHECK_DOMAIN, &v);
        v.extend_from_slice(&c);
        debug_assert_eq!(v.len(), n);
        Ok(v)
    }
    /// Check external domain bindings, checksum, full invariants and caller-committed canonical root.
    pub fn decode(
        b: &[u8],
        l: &StateLimits,
        net: &[u8; 32],
        manifest: &[u8; 32],
        gov: &[u8; 32],
        root: &[u8; 32],
    ) -> Result<Self, StateCodecError> {
        if b.len() > l.max_snapshot_bytes.min(STV3_MAX_BYTES) {
            return Err(StateCodecError::Limit("STV3 bytes"));
        }
        if b.len() < 356 {
            return Err(StateCodecError::Incomplete);
        }
        if &b[..4] != b"STV3" {
            return Err(StateCodecError::BadMagic);
        }
        let cs = b.len().checked_sub(32).ok_or(StateCodecError::Incomplete)?;
        if &b[cs..] != hash(CHECK_DOMAIN, &b[..cs]).as_slice() {
            return Err(StateCodecError::BadChecksum);
        }
        let mut p = 4;
        let v = r16(b, &mut p)?;
        if v != 3 {
            return Err(StateCodecError::Version(v));
        }
        let network_id = rbytes32(b, &mut p)?;
        if &network_id != net || zero(net) {
            return Err(StateCodecError::WrongNetwork);
        }
        let height = r64(b, &mut p)?;
        let last_timestamp = r64(b, &mut p)?;
        let body_tip_id = rbytes32(b, &mut p)?;
        let consensus_tip_digest = rbytes32(b, &mut p)?;
        let manifest_id = rbytes32(b, &mut p)?;
        if &manifest_id != manifest || zero(manifest) {
            return Err(StateCodecError::WrongManifest);
        }
        let governance_config_hash = rbytes32(b, &mut p)?;
        if &governance_config_hash != gov || zero(gov) {
            return Err(StateCodecError::WrongGovernanceConfig);
        }
        let total_issued_atoms = r64(b, &mut p)?;
        let miner_issued_atoms = r64(b, &mut p)?;
        let founder_issued_atoms = r64(b, &mut p)?;
        let mut public_goods_issued_atoms = [0; 6];
        for x in &mut public_goods_issued_atoms {
            *x = r64(b, &mut p)?
        }
        let total_burned_atoms = r64(b, &mut p)?;
        let mut proposer_nonce_highwater = [0; 7];
        for x in &mut proposer_nonce_highwater {
            *x = r64(b, &mut p)?
        }
        let n = r32(b, &mut p)? as usize;
        if n > l.max_accounts.min(MAX_ACCOUNTS) {
            return Err(StateCodecError::Limit("account count"));
        }
        let need = n
            .checked_mul(48)
            .and_then(|x| x.checked_add(2 + 32))
            .ok_or(StateCodecError::Overflow)?;
        if p.checked_add(need).ok_or(StateCodecError::Overflow)? > b.len() {
            return Err(StateCodecError::Incomplete);
        }
        let mut accounts = Vec::with_capacity(n);
        for _ in 0..n {
            accounts.push(AccountRecordV3 {
                account_id: rbytes32(b, &mut p)?,
                balance_atoms: r64(b, &mut p)?,
                nonce: r64(b, &mut p)?,
            })
        }
        let pn = r16(b, &mut p)? as usize;
        if pn > l.max_pending_proposals.min(MAX_PENDING_PROPOSALS) {
            return Err(StateCodecError::Limit("proposal count"));
        }
        let pbytes = pn
            .checked_mul(170)
            .and_then(|x| x.checked_add(32))
            .ok_or(StateCodecError::Overflow)?;
        let end = p.checked_add(pbytes).ok_or(StateCodecError::Overflow)?;
        if end > b.len() {
            return Err(StateCodecError::Incomplete);
        }
        if end < b.len() {
            return Err(StateCodecError::TrailingBytes);
        }
        let mut pending_proposals = Vec::with_capacity(pn);
        for _ in 0..pn {
            pending_proposals.push(PendingProposalV3::get(b, &mut p)?)
        }
        if p != cs {
            return Err(StateCodecError::TrailingBytes);
        }
        let s = StateV3 {
            network_id,
            height,
            last_timestamp,
            manifest_id,
            governance_config_hash,
            total_issued_atoms,
            miner_issued_atoms,
            founder_issued_atoms,
            public_goods_issued_atoms,
            total_burned_atoms,
            proposer_nonce_highwater,
            accounts,
            pending_proposals,
        };
        s.validate(l)?;
        if &s.state_root(l)? != root {
            return Err(StateCodecError::StateRootMismatch);
        }
        Ok(Self {
            state: s,
            body_tip_id,
            consensus_tip_digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const V: &str = include_str!("../../../../simulations/cp0217_stv3_state_vectors.tsv");
    fn vecv(k: &str) -> Vec<u8> {
        let l = V
            .lines()
            .find(|x| x.starts_with(&format!("{k}\t")))
            .unwrap_or_else(|| panic!("missing vector {k}"));
        let h = l.split_once('\t').unwrap().1.trim();
        (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
            .collect()
    }
    fn sample() -> StateV3 {
        StateV3 {
            network_id: [0x11; 32],
            height: 42,
            last_timestamp: 1_700_000_042,
            manifest_id: [0x77; 32],
            governance_config_hash: [0x88; 32],
            total_issued_atoms: 1_000_000,
            miner_issued_atoms: 400_000,
            founder_issued_atoms: 0,
            public_goods_issued_atoms: [10_000, 20_000, 30_000, 40_000, 50_000, 450_000],
            total_burned_atoms: 0,
            proposer_nonce_highwater: [1, 2, 3, 4, 5, 6, 7],
            accounts: vec![
                AccountRecordV3 {
                    account_id: [0x20; 32],
                    balance_atoms: 400_000,
                    nonce: 2,
                },
                AccountRecordV3 {
                    account_id: [0x30; 32],
                    balance_atoms: 600_000,
                    nonce: 3,
                },
            ],
            pending_proposals: vec![PendingProposalV3 {
                proposal_id: [0x10; 32],
                proposer_signer_id: [0x44; 32],
                proposer_nonce: 9,
                bucket_id: 2,
                recipient_id: [0x55; 32],
                amount_atoms: 999,
                rationale_hash: [0x66; 32],
                submitted_height: 40,
                not_before_height: 40 + TIMELOCK_BLOCKS,
                expires_height: 40 + TIMELOCK_BLOCKS + EXECUTION_WINDOW_BLOCKS,
                approval_bitmap: 1,
            }],
        }
    }
    fn snap() -> StateSnapshotV3 {
        StateSnapshotV3 {
            state: sample(),
            body_tip_id: [0x99; 32],
            consensus_tip_digest: [0xaa; 32],
        }
    }
    fn genesis() -> StateV3 {
        StateV3 {
            network_id: [0x11; 32],
            height: 0,
            last_timestamp: 0,
            manifest_id: [0x77; 32],
            governance_config_hash: [0x88; 32],
            total_issued_atoms: 0,
            miner_issued_atoms: 0,
            founder_issued_atoms: 0,
            public_goods_issued_atoms: [0; 6],
            total_burned_atoms: 0,
            proposer_nonce_highwater: [0; 7],
            accounts: vec![],
            pending_proposals: vec![],
        }
    }
    #[test]
    fn state_preimage_and_root_match_python() {
        let s = sample();
        assert_eq!(
            s.canonical_state_bytes(&StateLimits::default()).unwrap(),
            vecv("state_v3_preimage_hex")
        );
        assert_eq!(
            s.state_root(&StateLimits::default()).unwrap().to_vec(),
            vecv("state_v3_root_hex")
        )
    }
    #[test]
    fn stv3_full_bytes_checksum_and_roundtrip_match_python() {
        let x = snap();
        let b = x.encode(&StateLimits::default()).unwrap();
        assert_eq!(b.len(), 622);
        assert_eq!(b, vecv("stv3_hex"));
        assert_eq!(b[b.len() - 32..], vecv("stv3_checksum_hex"));
        let r = x.state.state_root(&StateLimits::default()).unwrap();
        assert_eq!(
            StateSnapshotV3::decode(
                &b,
                &StateLimits::default(),
                &[0x11; 32],
                &[0x77; 32],
                &[0x88; 32],
                &r
            )
            .unwrap(),
            x
        )
    }
    #[test]
    fn empty_genesis_root_matches_python() {
        let s = genesis();
        assert_eq!(
            s.canonical_state_bytes(&StateLimits::default()).unwrap(),
            vecv("genesis_state_v3_preimage_hex")
        );
        assert_eq!(
            s.state_root(&StateLimits::default()).unwrap().to_vec(),
            vecv("genesis_state_v3_root_hex")
        )
    }
    #[test]
    fn rejects_bad_sort_duplicate_ids_and_bitmap() {
        let mut s = sample();
        s.accounts.swap(0, 1);
        assert!(s.validate(&StateLimits::default()).is_err());
        let mut s = sample();
        s.accounts[1].account_id = s.accounts[0].account_id;
        assert!(s.state_root(&StateLimits::default()).is_err());
        let mut s = sample();
        s.accounts[0].account_id = [0; 32];
        assert!(s.state_root(&StateLimits::default()).is_err());
        let mut s = sample();
        s.pending_proposals[0].approval_bitmap = 0x81;
        assert!(s.state_root(&StateLimits::default()).is_err())
    }
    #[test]
    fn rejects_issuance_bucket_and_balance_invariants() {
        let mut s = sample();
        s.total_issued_atoms += 1;
        assert_eq!(
            s.validate(&StateLimits::default()),
            Err(StateCodecError::Invalid("issuance counter sum"))
        );
        let mut s = sample();
        s.accounts[0].balance_atoms -= 1;
        assert_eq!(
            s.validate(&StateLimits::default()),
            Err(StateCodecError::Invalid("account-balance conservation"))
        );
        let mut s = sample();
        let delta = 31_000_000_000_000_000u64 - 10_000;
        s.public_goods_issued_atoms[0] = 31_000_000_000_000_000;
        s.total_issued_atoms += delta;
        s.accounts[0].balance_atoms += delta;
        assert!(matches!(
            s.validate(&StateLimits::default()),
            Err(StateCodecError::Limit(_))
        ))
    }
    #[test]
    fn snapshot_rejects_checksum_network_manifest_governance_and_root() {
        let x = snap();
        let l = StateLimits::default();
        let r = x.state.state_root(&l).unwrap();
        let b = x.encode(&l).unwrap();
        let mut t = b.clone();
        t[100] ^= 1;
        assert_eq!(
            StateSnapshotV3::decode(&t, &l, &[0x11; 32], &[0x77; 32], &[0x88; 32], &r),
            Err(StateCodecError::BadChecksum)
        );
        assert_eq!(
            StateSnapshotV3::decode(&b, &l, &[0x12; 32], &[0x77; 32], &[0x88; 32], &r),
            Err(StateCodecError::WrongNetwork)
        );
        assert_eq!(
            StateSnapshotV3::decode(&b, &l, &[0x11; 32], &[0x78; 32], &[0x88; 32], &r),
            Err(StateCodecError::WrongManifest)
        );
        assert_eq!(
            StateSnapshotV3::decode(&b, &l, &[0x11; 32], &[0x77; 32], &[0x89; 32], &r),
            Err(StateCodecError::WrongGovernanceConfig)
        );
        assert_eq!(
            StateSnapshotV3::decode(&b, &l, &[0x11; 32], &[0x77; 32], &[0x88; 32], &[0x12; 32]),
            Err(StateCodecError::StateRootMismatch)
        )
    }
    #[test]
    fn snapshot_rejects_truncation_trailing_version_and_oversize() {
        let x = snap();
        let l = StateLimits::default();
        let r = x.state.state_root(&l).unwrap();
        let b = x.encode(&l).unwrap();
        assert_eq!(
            StateSnapshotV3::decode(
                &b[..b.len() - 1],
                &l,
                &[0x11; 32],
                &[0x77; 32],
                &[0x88; 32],
                &r
            ),
            Err(StateCodecError::BadChecksum)
        );
        let mut t = b.clone();
        t.push(0);
        assert_eq!(
            StateSnapshotV3::decode(&t, &l, &[0x11; 32], &[0x77; 32], &[0x88; 32], &r),
            Err(StateCodecError::BadChecksum)
        );
        let mut v = b.clone();
        v[4..6].copy_from_slice(&2u16.to_be_bytes());
        let c = hash(CHECK_DOMAIN, &v[..v.len() - 32]);
        let end = v.len();
        v[end - 32..].copy_from_slice(&c);
        assert_eq!(
            StateSnapshotV3::decode(&v, &l, &[0x11; 32], &[0x77; 32], &[0x88; 32], &r),
            Err(StateCodecError::Version(2))
        );
        let ll = StateLimits {
            max_snapshot_bytes: 400,
            ..l
        };
        assert!(matches!(x.encode(&ll), Err(StateCodecError::Limit(_))))
    }
    #[test]
    fn founder_schedule_and_genesis_zero_state_are_enforced() {
        let mut s = sample();
        s.founder_issued_atoms = 1;
        s.total_issued_atoms += 1;
        s.accounts[0].balance_atoms += 1;
        assert_eq!(
            s.validate(&StateLimits::default()),
            Err(StateCodecError::Invalid(
                "founder issuance exceeds height schedule"
            ))
        );
        assert_eq!(
            founder_due_atoms(1_138_800, 400_000_000_000_000_000).unwrap(),
            0
        );
        assert_eq!(
            founder_due_atoms(1_138_801, 400_000_000_000_000_000).unwrap(),
            8_333_333_333_333_333
        );
        let mut g = genesis();
        g.total_issued_atoms = 1;
        g.miner_issued_atoms = 1;
        g.accounts = vec![AccountRecordV3 {
            account_id: [0x20; 32],
            balance_atoms: 1,
            nonce: 0,
        }];
        assert!(matches!(
            g.validate(&StateLimits::default()),
            Err(StateCodecError::Invalid(
                "Genesis state must have zero counters and no records"
            ))
        ));
    }
    #[test]
    fn expired_pending_proposal_must_be_pruned_at_snapshot_height() {
        let mut s = sample();
        let expiry = s.pending_proposals[0].expires_height;
        s.height = expiry;
        assert!(s.validate(&StateLimits::default()).is_ok());
        s.height = expiry + 1;
        assert!(matches!(
            s.validate(&StateLimits::default()),
            Err(StateCodecError::Invalid(
                "expired proposal retained in state"
            ))
        ));
    }
    #[test]
    fn proposal_fields_are_checked() {
        let mut s = sample();
        s.pending_proposals[0].not_before_height += 1;
        assert_eq!(
            s.validate(&StateLimits::default()),
            Err(StateCodecError::Invalid("proposal timelock/expiry"))
        );
        let mut s = sample();
        s.pending_proposals[0].approval_bitmap = 0;
        assert!(s.validate(&StateLimits::default()).is_err());
        let mut s = sample();
        s.pending_proposals[0].bucket_id = 7;
        assert!(s.validate(&StateLimits::default()).is_err())
    }
}
