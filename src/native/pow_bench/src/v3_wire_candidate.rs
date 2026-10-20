//! CP-0216-V3C isolated V3 wire codec candidate.
//! Not connected to canonical admission, mining, fork choice, signatures or state transitions.
use sha2::{Digest, Sha256};

pub const TXN3_LEN: usize = 5_497;
pub const BLK3_HEADER_LEN: usize = 122;
pub const BLK3_MAX_LEN: usize = 8_388_608;
pub const PTB3_HEADER_LEN: usize = 228;
const SIG_LEN: usize = 3_373;
const PQ_PK_LEN: usize = 1_952;
const TX_SIGN: &[u8] = b"AIN1-TX-SIGN-V3\0";
const TX_ID: &[u8] = b"AIN1-TX-ID-V3\0";
const ACCOUNT_ID: &[u8] = b"AIN1-ACCOUNT-ID-V3\0";
const BLOCK_ID: &[u8] = b"AIN1-BLOCK-ID-V3\0";
const POW: &[u8] = b"AIN1-POW-V3\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    Incomplete,
    TrailingBytes,
    BadMagic,
    Version(u16),
    WrongNetwork,
    Invalid(&'static str),
    Length(&'static str),
    Limit(&'static str),
    ActionOrder,
    Overflow,
}

fn zero(b: &[u8]) -> bool {
    b.iter().all(|x| *x == 0)
}
fn take<'a>(b: &'a [u8], p: &mut usize, n: usize) -> Result<&'a [u8], CodecError> {
    let end = (*p).checked_add(n).ok_or(CodecError::Overflow)?;
    let x = b.get(*p..end).ok_or(CodecError::Incomplete)?;
    *p = end;
    Ok(x)
}
fn u16r(b: &[u8], p: &mut usize) -> Result<u16, CodecError> {
    Ok(u16::from_be_bytes(
        take(b, p, 2)?.try_into().expect("fixed"),
    ))
}
fn u32r(b: &[u8], p: &mut usize) -> Result<u32, CodecError> {
    Ok(u32::from_be_bytes(
        take(b, p, 4)?.try_into().expect("fixed"),
    ))
}
fn u64r(b: &[u8], p: &mut usize) -> Result<u64, CodecError> {
    Ok(u64::from_be_bytes(
        take(b, p, 8)?.try_into().expect("fixed"),
    ))
}
fn a32(b: &[u8], p: &mut usize) -> Result<[u8; 32], CodecError> {
    Ok(take(b, p, 32)?.try_into().expect("fixed"))
}
fn hash(domain: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(b);
    h.finalize().into()
}

pub fn derive_account_id(ed: &[u8; 32], pq: &[u8]) -> Result<[u8; 32], CodecError> {
    if pq.len() != PQ_PK_LEN {
        return Err(CodecError::Length("ML-DSA-65 public key"));
    }
    let mut h = Sha256::new();
    h.update(ACCOUNT_ID);
    h.update(3u16.to_be_bytes());
    h.update(ed);
    h.update(pq);
    Ok(h.finalize().into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Txn3 {
    pub network_id: [u8; 32],
    pub sender_id: [u8; 32],
    pub recipient_id: [u8; 32],
    pub nonce: u64,
    pub amount_atoms: u64,
    pub fee_atoms: u64,
    pub expires_at: u64,
    pub ed_pk: [u8; 32],
    pub pq_pk: Vec<u8>,
    pub ed_sig: Vec<u8>,
    pub pq_sig: Vec<u8>,
}
impl Txn3 {
    fn valid(&self) -> Result<(), CodecError> {
        if zero(&self.network_id)
            || zero(&self.recipient_id)
            || self.nonce == 0
            || self.amount_atoms == 0
            || self.expires_at == 0
        {
            return Err(CodecError::Invalid("required TXN3 field"));
        }
        if self.sender_id != derive_account_id(&self.ed_pk, &self.pq_pk)? {
            return Err(CodecError::Invalid("sender key binding"));
        }
        if self.ed_sig.len() != 64 || self.pq_sig.len() != SIG_LEN - 64 {
            return Err(CodecError::Length("hybrid signature"));
        }
        Ok(())
    }
    fn unsigned(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(2122);
        v.extend_from_slice(b"TXN3");
        v.extend_from_slice(&3u16.to_be_bytes());
        v.extend_from_slice(&self.network_id);
        v.extend_from_slice(&self.sender_id);
        v.extend_from_slice(&self.recipient_id);
        v.extend_from_slice(&self.nonce.to_be_bytes());
        v.extend_from_slice(&self.amount_atoms.to_be_bytes());
        v.extend_from_slice(&self.fee_atoms.to_be_bytes());
        v.extend_from_slice(&self.expires_at.to_be_bytes());
        v.extend_from_slice(&3u16.to_be_bytes());
        v.extend_from_slice(&1984u16.to_be_bytes());
        v.extend_from_slice(&self.ed_pk);
        v.extend_from_slice(&self.pq_pk);
        v
    }
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.valid()?;
        let mut v = self.unsigned();
        v.extend_from_slice(&(SIG_LEN as u16).to_be_bytes());
        v.extend_from_slice(&self.ed_sig);
        v.extend_from_slice(&self.pq_sig);
        if v.len() != TXN3_LEN {
            return Err(CodecError::Length("TXN3 encoded size"));
        }
        Ok(v)
    }
    pub fn decode(b: &[u8], net: &[u8; 32]) -> Result<Self, CodecError> {
        if b.len() < TXN3_LEN {
            return Err(CodecError::Incomplete);
        }
        if b.len() > TXN3_LEN {
            return Err(CodecError::TrailingBytes);
        }
        if &b[..4] != b"TXN3" {
            return Err(CodecError::BadMagic);
        }
        let mut p = 4;
        let ver = u16r(b, &mut p)?;
        if ver != 3 {
            return Err(CodecError::Version(ver));
        }
        let network_id = a32(b, &mut p)?;
        if &network_id != net || zero(net) {
            return Err(CodecError::WrongNetwork);
        }
        let sender_id = a32(b, &mut p)?;
        let recipient_id = a32(b, &mut p)?;
        let nonce = u64r(b, &mut p)?;
        let amount_atoms = u64r(b, &mut p)?;
        let fee_atoms = u64r(b, &mut p)?;
        let expires_at = u64r(b, &mut p)?;
        if u16r(b, &mut p)? != 3 {
            return Err(CodecError::Invalid("auth suite"));
        }
        if u16r(b, &mut p)? != 1984 {
            return Err(CodecError::Length("key material"));
        }
        let ed_pk: [u8; 32] = take(b, &mut p, 32)?.try_into().expect("fixed");
        let pq_pk = take(b, &mut p, PQ_PK_LEN)?.to_vec();
        if u16r(b, &mut p)? as usize != SIG_LEN {
            return Err(CodecError::Length("signature length"));
        }
        let ed_sig = take(b, &mut p, 64)?.to_vec();
        let pq_sig = take(b, &mut p, SIG_LEN - 64)?.to_vec();
        if p != b.len() {
            return Err(CodecError::TrailingBytes);
        }
        let t = Self {
            network_id,
            sender_id,
            recipient_id,
            nonce,
            amount_atoms,
            fee_atoms,
            expires_at,
            ed_pk,
            pq_pk,
            ed_sig,
            pq_sig,
        };
        t.valid()?;
        Ok(t)
    }
    pub fn signing_digest(&self) -> Result<[u8; 32], CodecError> {
        self.valid()?;
        Ok(hash(TX_SIGN, &self.unsigned()))
    }
    pub fn transaction_id(&self) -> Result<[u8; 32], CodecError> {
        Ok(hash(TX_ID, &self.encode()?))
    }
}

fn check_action(b: &[u8]) -> Result<(), CodecError> {
    if b.len() < 6 {
        return Err(CodecError::Incomplete);
    }
    let ver = u16::from_be_bytes([b[4], b[5]]);
    if ver != 3 {
        return Err(CodecError::Version(ver));
    }
    match &b[..4] {
        b"GPR3" => {
            if b.len() != 3528 {
                return Err(CodecError::Length("GPR3"));
            }
            if b[78] == 0
                || b[78] > 6
                || zero(&b[38..70])
                || zero(&b[79..111])
                || u64::from_be_bytes(b[70..78].try_into().expect("fixed")) == 0
                || u64::from_be_bytes(b[111..119].try_into().expect("fixed")) == 0
            {
                return Err(CodecError::Invalid("GPR3 field"));
            }
            if u16::from_be_bytes(b[151..153].try_into().expect("fixed")) != 3
                || u16::from_be_bytes(b[153..155].try_into().expect("fixed")) as usize != SIG_LEN
            {
                return Err(CodecError::Invalid("GPR3 signature framing"));
            }
        }
        b"GAP3" => {
            if b.len() != 3479 {
                return Err(CodecError::Length("GAP3"));
            }
            if zero(&b[6..38])
                || zero(&b[38..70])
                || zero(&b[70..102])
                || u16::from_be_bytes(b[102..104].try_into().expect("fixed")) != 3
                || u16::from_be_bytes(b[104..106].try_into().expect("fixed")) as usize != SIG_LEN
            {
                return Err(CodecError::Invalid("GAP3 field"));
            }
        }
        b"GEX3" => {
            if b.len() != 70 {
                return Err(CodecError::Length("GEX3"));
            }
            if zero(&b[6..38]) || zero(&b[38..70]) {
                return Err(CodecError::Invalid("GEX3 id"));
            }
        }
        _ => return Err(CodecError::Invalid("unknown governance action")),
    }
    Ok(())
}
fn action_sort_key(a: &[u8]) -> Result<Vec<u8>, CodecError> {
    check_action(a)?;
    let mut key = Vec::with_capacity(73);
    match &a[..4] {
        b"GPR3" => {
            key.push(0);
            key.extend_from_slice(&a[38..70]); // proposer signer ID
            key.extend_from_slice(&a[70..78]); // proposer nonce, unsigned big-endian
        }
        b"GAP3" => {
            key.push(1);
            key.extend_from_slice(&a[38..70]); // proposal ID
            key.extend_from_slice(&a[70..102]); // signer ID
        }
        b"GEX3" => {
            key.push(2);
            key.extend_from_slice(&a[38..70]); // proposal ID
        }
        _ => return Err(CodecError::Invalid("unknown governance action")),
    }
    Ok(key)
}
fn actions_valid(a: &[Vec<u8>]) -> Result<(), CodecError> {
    if a.len() > 64 {
        return Err(CodecError::Limit("actions"));
    }
    let keys = a
        .iter()
        .map(|x| action_sort_key(x))
        .collect::<Result<Vec<_>, _>>()?;
    if keys.windows(2).any(|w| w[0] >= w[1]) {
        return Err(CodecError::ActionOrder);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block3 {
    pub network_id: [u8; 32],
    pub height: u64,
    pub timestamp: u64,
    pub parent_body_id: [u8; 32],
    pub post_state_root: [u8; 32],
    pub transactions: Vec<Txn3>,
    pub actions: Vec<Vec<u8>>,
}
impl Block3 {
    fn valid(&self) -> Result<(), CodecError> {
        if zero(&self.network_id) || self.height == 0 || self.timestamp == 0 {
            return Err(CodecError::Invalid("BLK3 context"));
        }
        if self.transactions.len() > 1024 {
            return Err(CodecError::Limit("transactions"));
        }
        actions_valid(&self.actions)?;
        for t in &self.transactions {
            if t.network_id != self.network_id {
                return Err(CodecError::WrongNetwork);
            }
            t.valid()?
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.valid()?;
        let mut v = Vec::new();
        v.extend_from_slice(b"BLK3");
        v.extend_from_slice(&3u16.to_be_bytes());
        v.extend_from_slice(&self.network_id);
        v.extend_from_slice(&self.height.to_be_bytes());
        v.extend_from_slice(&self.timestamp.to_be_bytes());
        v.extend_from_slice(&self.parent_body_id);
        v.extend_from_slice(&self.post_state_root);
        v.extend_from_slice(&(self.transactions.len() as u16).to_be_bytes());
        v.extend_from_slice(&(self.actions.len() as u16).to_be_bytes());
        for t in &self.transactions {
            let x = t.encode()?;
            v.extend_from_slice(&(x.len() as u32).to_be_bytes());
            v.extend_from_slice(&x)
        }
        for a in &self.actions {
            v.extend_from_slice(&(a.len() as u32).to_be_bytes());
            v.extend_from_slice(a)
        }
        if v.len() > BLK3_MAX_LEN {
            return Err(CodecError::Limit("BLK3 bytes"));
        }
        Ok(v)
    }
    pub fn decode(b: &[u8], net: &[u8; 32]) -> Result<Self, CodecError> {
        if b.len() < BLK3_HEADER_LEN {
            return Err(CodecError::Incomplete);
        }
        if b.len() > BLK3_MAX_LEN {
            return Err(CodecError::Limit("BLK3 bytes"));
        }
        if &b[..4] != b"BLK3" {
            return Err(CodecError::BadMagic);
        }
        let mut p = 4;
        let ver = u16r(b, &mut p)?;
        if ver != 3 {
            return Err(CodecError::Version(ver));
        }
        let network_id = a32(b, &mut p)?;
        if &network_id != net || zero(net) {
            return Err(CodecError::WrongNetwork);
        }
        let height = u64r(b, &mut p)?;
        let timestamp = u64r(b, &mut p)?;
        let parent_body_id = a32(b, &mut p)?;
        let post_state_root = a32(b, &mut p)?;
        let nt = u16r(b, &mut p)? as usize;
        let na = u16r(b, &mut p)? as usize;
        if nt > 1024 {
            return Err(CodecError::Limit("transactions"));
        }
        if na > 64 {
            return Err(CodecError::Limit("actions"));
        }
        let mut transactions = Vec::with_capacity(nt);
        for _ in 0..nt {
            let n = u32r(b, &mut p)? as usize;
            if n != TXN3_LEN {
                return Err(CodecError::Length("nested TXN3"));
            }
            transactions.push(Txn3::decode(take(b, &mut p, n)?, net)?)
        }
        let mut actions = Vec::with_capacity(na);
        for _ in 0..na {
            let n = u32r(b, &mut p)? as usize;
            if n > 3528 {
                return Err(CodecError::Length("action"));
            }
            let x = take(b, &mut p, n)?.to_vec();
            check_action(&x)?;
            actions.push(x)
        }
        if p != b.len() {
            return Err(CodecError::TrailingBytes);
        }
        let x = Self {
            network_id,
            height,
            timestamp,
            parent_body_id,
            post_state_root,
            transactions,
            actions,
        };
        x.valid()?;
        Ok(x)
    }
    pub fn body_id(&self) -> Result<[u8; 32], CodecError> {
        Ok(hash(BLOCK_ID, &self.encode()?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ptb3 {
    pub network_id: [u8; 32],
    pub height: u64,
    pub timestamp: u64,
    pub parent_body_id: [u8; 32],
    pub previous_consensus_hash: [u8; 32],
    pub post_state_root: [u8; 32],
    pub target: [u8; 32],
    pub nonce: u64,
    pub reward_beneficiary_id: [u8; 32],
    pub body: Block3,
}
impl Ptb3 {
    fn valid(&self) -> Result<(), CodecError> {
        self.body.valid()?;
        if zero(&self.network_id) || self.network_id != self.body.network_id {
            return Err(CodecError::WrongNetwork);
        }
        if self.height == 0
            || self.timestamp == 0
            || self.height != self.body.height
            || self.timestamp != self.body.timestamp
            || self.parent_body_id != self.body.parent_body_id
            || self.post_state_root != self.body.post_state_root
        {
            return Err(CodecError::Invalid("PTB3/BLK3 mismatch"));
        }
        if zero(&self.target) || zero(&self.reward_beneficiary_id) {
            return Err(CodecError::Invalid("PTB3 target or beneficiary"));
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.valid()?;
        let b = self.body.encode()?;
        let mut v = Vec::with_capacity(PTB3_HEADER_LEN + b.len());
        v.extend_from_slice(b"PTB3");
        v.extend_from_slice(&3u16.to_be_bytes());
        v.extend_from_slice(&3u16.to_be_bytes());
        v.extend_from_slice(&self.network_id);
        v.extend_from_slice(&self.height.to_be_bytes());
        v.extend_from_slice(&self.timestamp.to_be_bytes());
        v.extend_from_slice(&self.parent_body_id);
        v.extend_from_slice(&self.previous_consensus_hash);
        v.extend_from_slice(&self.post_state_root);
        v.extend_from_slice(&self.target);
        v.extend_from_slice(&self.nonce.to_be_bytes());
        v.extend_from_slice(&self.reward_beneficiary_id);
        v.extend_from_slice(&(b.len() as u32).to_be_bytes());
        debug_assert_eq!(v.len(), PTB3_HEADER_LEN);
        v.extend_from_slice(&b);
        Ok(v)
    }
    pub fn decode(b: &[u8], net: &[u8; 32]) -> Result<Self, CodecError> {
        if b.len() < PTB3_HEADER_LEN {
            return Err(CodecError::Incomplete);
        }
        if &b[..4] != b"PTB3" {
            return Err(CodecError::BadMagic);
        }
        let mut p = 4;
        let w = u16r(b, &mut p)?;
        if w != 3 {
            return Err(CodecError::Version(w));
        }
        let pr = u16r(b, &mut p)?;
        if pr != 3 {
            return Err(CodecError::Version(pr));
        }
        let network_id = a32(b, &mut p)?;
        if &network_id != net || zero(net) {
            return Err(CodecError::WrongNetwork);
        }
        let height = u64r(b, &mut p)?;
        let timestamp = u64r(b, &mut p)?;
        let parent_body_id = a32(b, &mut p)?;
        let previous_consensus_hash = a32(b, &mut p)?;
        let post_state_root = a32(b, &mut p)?;
        let target = a32(b, &mut p)?;
        let nonce = u64r(b, &mut p)?;
        let reward_beneficiary_id = a32(b, &mut p)?;
        let n = u32r(b, &mut p)? as usize;
        if n > BLK3_MAX_LEN {
            return Err(CodecError::Limit("PTB3 body"));
        }
        let total = PTB3_HEADER_LEN.checked_add(n).ok_or(CodecError::Overflow)?;
        if b.len() < total {
            return Err(CodecError::Incomplete);
        }
        if b.len() > total {
            return Err(CodecError::TrailingBytes);
        }
        let body = Block3::decode(take(b, &mut p, n)?, net)?;
        let x = Self {
            network_id,
            height,
            timestamp,
            parent_body_id,
            previous_consensus_hash,
            post_state_root,
            target,
            nonce,
            reward_beneficiary_id,
            body,
        };
        x.valid()?;
        Ok(x)
    }
    pub fn pow_preimage(&self) -> Result<Vec<u8>, CodecError> {
        self.valid()?;
        let mut v = Vec::with_capacity(230);
        v.extend_from_slice(POW);
        v.extend_from_slice(&3u16.to_be_bytes());
        v.extend_from_slice(&self.network_id);
        v.extend_from_slice(&self.height.to_be_bytes());
        v.extend_from_slice(&self.timestamp.to_be_bytes());
        v.extend_from_slice(&self.parent_body_id);
        v.extend_from_slice(&self.previous_consensus_hash);
        v.extend_from_slice(&self.post_state_root);
        v.extend_from_slice(&self.target);
        v.extend_from_slice(&self.nonce.to_be_bytes());
        v.extend_from_slice(&self.reward_beneficiary_id);
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const V: &str = include_str!("../../../../simulations/cp0216_v3_wire_vectors.tsv");
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
    fn tx() -> Txn3 {
        let ed = [0x22; 32];
        let pq = vec![0x23; PQ_PK_LEN];
        Txn3 {
            network_id: [0x11; 32],
            sender_id: derive_account_id(&ed, &pq).unwrap(),
            recipient_id: [0x33; 32],
            nonce: 7,
            amount_atoms: 123456789,
            fee_atoms: 1234,
            expires_at: 987654321,
            ed_pk: ed,
            pq_pk: pq,
            ed_sig: vec![0x44; 64],
            pq_sig: vec![0x45; SIG_LEN - 64],
        }
    }
    fn act() -> Vec<u8> {
        let mut a = Vec::new();
        a.extend_from_slice(b"GEX3");
        a.extend_from_slice(&3u16.to_be_bytes());
        a.extend_from_slice(&[0x77; 32]);
        a.extend_from_slice(&[0x88; 32]);
        a
    }
    fn blk() -> Block3 {
        Block3 {
            network_id: [0x11; 32],
            height: 42,
            timestamp: 1700000042,
            parent_body_id: [0x55; 32],
            post_state_root: [0x66; 32],
            transactions: vec![tx()],
            actions: vec![act()],
        }
    }
    fn ptb() -> Ptb3 {
        let mut target = [0xff; 32];
        target[0] = 0;
        target[1] = 0x7f;
        Ptb3 {
            network_id: [0x11; 32],
            height: 42,
            timestamp: 1700000042,
            parent_body_id: [0x55; 32],
            previous_consensus_hash: [0x99; 32],
            post_state_root: [0x66; 32],
            target,
            nonce: 123,
            reward_beneficiary_id: [0xaa; 32],
            body: blk(),
        }
    }
    #[test]
    fn txn_golden_and_roundtrip() {
        let t = tx();
        let b = t.encode().unwrap();
        assert_eq!(b.len(), TXN3_LEN);
        assert_eq!(b, vecv("txn3_hex"));
        assert_eq!(
            t.signing_digest().unwrap().to_vec(),
            vecv("txn3_signing_digest_hex")
        );
        assert_eq!(t.transaction_id().unwrap().to_vec(), vecv("txn3_id_hex"));
        assert_eq!(Txn3::decode(&b, &[0x11; 32]).unwrap(), t)
    }
    #[test]
    fn txn_rejects_truncation_trailing_network_and_sender_mismatch() {
        let b = tx().encode().unwrap();
        assert_eq!(
            Txn3::decode(&b[..b.len() - 1], &[0x11; 32]),
            Err(CodecError::Incomplete)
        );
        let mut x = b.clone();
        x.push(0);
        assert_eq!(
            Txn3::decode(&x, &[0x11; 32]),
            Err(CodecError::TrailingBytes)
        );
        assert_eq!(Txn3::decode(&b, &[0x12; 32]), Err(CodecError::WrongNetwork));
        let mut x = b;
        x[38] ^= 1;
        assert!(matches!(
            Txn3::decode(&x, &[0x11; 32]),
            Err(CodecError::Invalid(_))
        ))
    }
    #[test]
    fn blk_golden_hash_and_roundtrip() {
        let x = blk();
        let b = x.encode().unwrap();
        assert_eq!(b, vecv("blk3_hex"));
        assert_eq!(x.body_id().unwrap().to_vec(), vecv("blk3_id_hex"));
        assert_eq!(Block3::decode(&b, &[0x11; 32]).unwrap(), x)
    }
    #[test]
    fn blk_action_order_and_trailing_rejected() {
        let mut x = blk();
        let mut a = act();
        a[69] = 1;
        let mut b = act();
        b[69] = 2;
        x.actions = vec![b.clone(), a.clone()];
        assert_eq!(x.encode(), Err(CodecError::ActionOrder));
        x.actions = vec![a, b];
        assert!(x.encode().is_ok());
        let mut b = blk().encode().unwrap();
        b.push(0);
        assert_eq!(
            Block3::decode(&b, &[0x11; 32]),
            Err(CodecError::TrailingBytes)
        )
    }
    #[test]
    fn ptb_golden_pow_and_roundtrip() {
        let x = ptb();
        let b = x.encode().unwrap();
        assert_eq!(b, vecv("ptb3_hex"));
        assert_eq!(x.pow_preimage().unwrap(), vecv("ptb3_pow_preimage_hex"));
        assert_eq!(Ptb3::decode(&b, &[0x11; 32]).unwrap(), x)
    }
    fn fake_gpr(signer: u8, nonce: u64) -> Vec<u8> {
        let mut b = vec![0u8; 3528];
        b[..4].copy_from_slice(b"GPR3");
        b[4..6].copy_from_slice(&3u16.to_be_bytes());
        b[6..38].fill(0x11);
        b[38..70].fill(signer);
        b[70..78].copy_from_slice(&nonce.to_be_bytes());
        b[78] = 1;
        b[79..111].fill(0x30);
        b[111..119].copy_from_slice(&1u64.to_be_bytes());
        b[119..151].fill(0x40);
        b[151..153].copy_from_slice(&3u16.to_be_bytes());
        b[153..155].copy_from_slice(&3373u16.to_be_bytes());
        b
    }
    fn fake_gap(proposal: u8, signer: u8) -> Vec<u8> {
        let mut b = vec![0u8; 3479];
        b[..4].copy_from_slice(b"GAP3");
        b[4..6].copy_from_slice(&3u16.to_be_bytes());
        b[6..38].fill(0x11);
        b[38..70].fill(proposal);
        b[70..102].fill(signer);
        b[102..104].copy_from_slice(&3u16.to_be_bytes());
        b[104..106].copy_from_slice(&3373u16.to_be_bytes());
        b
    }
    #[test]
    fn governance_actions_follow_phase_and_phase_specific_order_keys() {
        let p1 = fake_gpr(0x10, 1);
        let p2 = fake_gpr(0x20, 1);
        let a1 = fake_gap(0x30, 0x10);
        let a2 = fake_gap(0x30, 0x20);
        let e1 = act();
        assert!(
            actions_valid(&[p1.clone(), p2.clone(), a1.clone(), a2.clone(), e1.clone()]).is_ok()
        );
        assert_eq!(
            actions_valid(&[e1.clone(), p1.clone(), a1.clone()]),
            Err(CodecError::ActionOrder)
        );
        assert_eq!(
            actions_valid(&[p2.clone(), p1.clone()]),
            Err(CodecError::ActionOrder)
        );
        assert_eq!(
            actions_valid(&[p1.clone(), p1.clone()]),
            Err(CodecError::ActionOrder)
        );
        assert_eq!(
            actions_valid(&[a2.clone(), a1.clone()]),
            Err(CodecError::ActionOrder)
        );
        let mut e2 = e1.clone();
        e2[69] = e1[69] + 1;
        assert!(actions_valid(&[e1.clone(), e2.clone()]).is_ok());
        assert_eq!(actions_valid(&[e2, e1]), Err(CodecError::ActionOrder));
    }
    #[test]
    fn beneficiary_binding_and_bad_version() {
        let mut x = ptb();
        let a = x.pow_preimage().unwrap();
        x.reward_beneficiary_id[0] ^= 1;
        assert_ne!(x.pow_preimage().unwrap(), a);
        let mut b = tx().encode().unwrap();
        b[4..6].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(Txn3::decode(&b, &[0x11; 32]), Err(CodecError::Version(2)))
    }

    #[test]
    fn all_governance_action_frames_validate() {
        fn proposal() -> Vec<u8> {
            let mut b = Vec::new();
            b.extend_from_slice(b"GPR3");
            b.extend_from_slice(&3u16.to_be_bytes());
            b.extend_from_slice(&[0x10; 32]);
            b.extend_from_slice(&[0x20; 32]);
            b.extend_from_slice(&1u64.to_be_bytes());
            b.push(1);
            b.extend_from_slice(&[0x30; 32]);
            b.extend_from_slice(&50u64.to_be_bytes());
            b.extend_from_slice(&[0x40; 32]);
            b.extend_from_slice(&3u16.to_be_bytes());
            b.extend_from_slice(&(SIG_LEN as u16).to_be_bytes());
            b.extend_from_slice(&[0x44; 64]);
            b.extend_from_slice(&vec![0x45; SIG_LEN - 64]);
            assert_eq!(b.len(), 3528);
            b
        }
        fn approval() -> Vec<u8> {
            let mut b = Vec::new();
            b.extend_from_slice(b"GAP3");
            b.extend_from_slice(&3u16.to_be_bytes());
            b.extend_from_slice(&[0x10; 32]);
            b.extend_from_slice(&[0x50; 32]);
            b.extend_from_slice(&[0x20; 32]);
            b.extend_from_slice(&3u16.to_be_bytes());
            b.extend_from_slice(&(SIG_LEN as u16).to_be_bytes());
            b.extend_from_slice(&[0x44; 64]);
            b.extend_from_slice(&vec![0x45; SIG_LEN - 64]);
            assert_eq!(b.len(), 3479);
            b
        }
        let actions = vec![proposal(), approval(), act()];
        actions_valid(&actions).unwrap();
        let mut malformed = proposal();
        malformed[153..155].copy_from_slice(&2u16.to_be_bytes());
        assert!(matches!(
            check_action(&malformed),
            Err(CodecError::Invalid(_))
        ));
        let mut malformed = approval();
        malformed[104..106].copy_from_slice(&1u16.to_be_bytes());
        assert!(matches!(
            check_action(&malformed),
            Err(CodecError::Invalid(_))
        ));
    }
}
