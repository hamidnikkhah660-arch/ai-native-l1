//! Isolated QRun v0.6 deterministic LOB candidate. Not wired into QFP5/QFB5.
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;

pub type AssetId = [u8; 32];
pub type AccountId = [u8; 32];
pub type PairId = [u8; 32];
pub type OrderId = [u8; 32];
pub type FillId = [u8; 32];

const PAIR_DOMAIN: &[u8] = b"QRUN-V06-LOB-PAIR\0";
const ORDER_DOMAIN: &[u8] = b"QRUN-V06-LOB-ORDER\0";
const FILL_DOMAIN: &[u8] = b"QRUN-V06-LOB-FILL\0";
const ROOT_DOMAIN: &[u8] = b"QRUN-V06-LOB-ROOT-CANDIDATE\0";
const SNAPSHOT_MAGIC: [u8; 4] = *b"Q6OB";
const SNAPSHOT_VERSION: u16 = 1;
const SNAPSHOT_CHECKSUM_DOMAIN: &[u8] = b"QRUN-V06-ORDERBOOK-SNAPSHOT-CHECKSUM-V1\0";
pub const MAX_QRUN_V06_ORDERBOOK_SNAPSHOT_BYTES: usize = 32 * 1024 * 1024;
const MAX_ORDERBOOK_SNAPSHOT_ENTRIES: usize = 65_536;
const BPS: u128 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Buy,
    Sell,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tif {
    Gtc,
    Ioc,
    Fok,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Priority {
    pub height: u64,
    pub tx_index: u32,
    pub op_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidConfig,
    InvalidAsset,
    InvalidAccount,
    PairNotFound,
    DuplicatePair,
    InvalidPrice,
    InvalidQuantity,
    InvalidExpiry,
    InvalidPriority,
    Malformed,
    Oversize,
    DuplicateOrder,
    OrderNotFound,
    NotOwner,
    SelfTrade,
    ExpiryNotProcessed,
    InsufficientBalance,
    InsufficientLiquidity,
    Overflow,
    Underflow,
    TooManyOrders,
    TooManyFills,
    Invariant,
    SnapshotMalformed,
    SnapshotChecksumMismatch,
    SnapshotNonCanonical,
    SnapshotOversize,
    WrongNetwork,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairRules {
    pub id: PairId,
    pub base: AssetId,
    pub quote: AssetId,
    pub base_lot_atoms: u128,
    pub quote_tick_atoms: u128,
    pub max_price_ticks: u128,
    pub max_quantity_lots: u128,
    pub min_notional: u128,
    pub maker_fee_bps: u16,
    pub taker_fee_bps: u16,
    pub fee_collector: AccountId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaceLimit {
    pub pair: PairId,
    pub owner: AccountId,
    pub side: Side,
    pub price_ticks: u128,
    pub quantity_lots: u128,
    pub tif: Tif,
    pub expires_at_height: u64,
    pub priority: Priority,
    pub transaction_id: [u8; 32],
    pub operation_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Order {
    pub id: OrderId,
    pub pair: PairId,
    pub owner: AccountId,
    pub side: Side,
    pub price_ticks: u128,
    pub original_lots: u128,
    pub remaining_lots: u128,
    pub priority: Priority,
    pub expires_at_height: u64,
    pub locked_atoms: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fill {
    pub id: FillId,
    pub pair: PairId,
    pub maker_order: OrderId,
    pub taker_order: OrderId,
    pub buyer: AccountId,
    pub seller: AccountId,
    pub price_ticks: u128,
    pub quantity_lots: u128,
    pub base_atoms: u128,
    pub quote_atoms: u128,
    pub buyer_fee: u128,
    pub seller_fee: u128,
    pub match_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaceResult {
    pub order_id: OrderId,
    pub filled_lots: u128,
    pub remaining_lots: u128,
    pub fill_ids: Vec<FillId>,
}

const SIGNED_OP_MAGIC: [u8; 4] = *b"QOB6";
const SIGNED_OP_VERSION: u16 = 1;
const SIGNED_OP_DOMAIN: &[u8] = b"QRUN-V06-ORDERBOOK-SIGNED-OP\0";
const MAX_SIGNED_OP_BYTES: usize = 16 * 1024;
const MAX_SIGNED_SIGNATURE_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06OrderBookOperation {
    CreatePair {
        base: AssetId,
        quote: AssetId,
        base_lot_atoms: u128,
        quote_tick_atoms: u128,
        max_price_ticks: u128,
        max_quantity_lots: u128,
        min_notional: u128,
        maker_fee_bps: u16,
        taker_fee_bps: u16,
        fee_collector: AccountId,
    },
    Deposit {
        asset: AssetId,
        amount: u128,
    },
    Withdraw {
        asset: AssetId,
        amount: u128,
    },
    PlaceLimit {
        pair: PairId,
        side: Side,
        price_ticks: u128,
        quantity_lots: u128,
        tif: Tif,
        expires_at_height: u64,
    },
    Cancel {
        order_id: OrderId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06SignedOrderBookOperation {
    pub network_id: [u8; 32],
    pub sender: AccountId,
    pub nonce: u64,
    pub expires_at: u64,
    pub operation: QRunV06OrderBookOperation,
    pub signature: Vec<u8>,
}

impl QRunV06SignedOrderBookOperation {
    pub fn operation_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(192);
        match &self.operation {
            QRunV06OrderBookOperation::CreatePair {
                base,
                quote,
                base_lot_atoms,
                quote_tick_atoms,
                max_price_ticks,
                max_quantity_lots,
                min_notional,
                maker_fee_bps,
                taker_fee_bps,
                fee_collector,
            } => {
                out.push(1);
                out.extend_from_slice(base);
                out.extend_from_slice(quote);
                out.extend_from_slice(&base_lot_atoms.to_be_bytes());
                out.extend_from_slice(&quote_tick_atoms.to_be_bytes());
                out.extend_from_slice(&max_price_ticks.to_be_bytes());
                out.extend_from_slice(&max_quantity_lots.to_be_bytes());
                out.extend_from_slice(&min_notional.to_be_bytes());
                out.extend_from_slice(&maker_fee_bps.to_be_bytes());
                out.extend_from_slice(&taker_fee_bps.to_be_bytes());
                out.extend_from_slice(fee_collector);
            }
            QRunV06OrderBookOperation::Deposit { asset, amount } => {
                out.push(2);
                out.extend_from_slice(asset);
                out.extend_from_slice(&amount.to_be_bytes());
            }
            QRunV06OrderBookOperation::Withdraw { asset, amount } => {
                out.push(3);
                out.extend_from_slice(asset);
                out.extend_from_slice(&amount.to_be_bytes());
            }
            QRunV06OrderBookOperation::PlaceLimit {
                pair,
                side,
                price_ticks,
                quantity_lots,
                tif,
                expires_at_height,
            } => {
                out.push(4);
                out.extend_from_slice(pair);
                out.push(side_tag(*side));
                out.extend_from_slice(&price_ticks.to_be_bytes());
                out.extend_from_slice(&quantity_lots.to_be_bytes());
                out.push(tif_tag(*tif));
                out.extend_from_slice(&expires_at_height.to_be_bytes());
            }
            QRunV06OrderBookOperation::Cancel { order_id } => {
                out.push(5);
                out.extend_from_slice(order_id);
            }
        }
        if out.len() > MAX_SIGNED_OP_BYTES {
            return Err(Error::Oversize);
        }
        Ok(out)
    }

    pub fn signing_digest(&self) -> Result<[u8; 32], Error> {
        if zero(&self.network_id) || zero(&self.sender) || self.nonce == 0 || self.expires_at == 0 {
            return Err(Error::InvalidPriority);
        }
        let operation = self.operation_bytes()?;
        let mut hash = Sha256::new();
        hash.update(SIGNED_OP_DOMAIN);
        hash.update(self.network_id);
        hash.update(self.sender);
        hash.update(self.nonce.to_be_bytes());
        hash.update(self.expires_at.to_be_bytes());
        hash.update((operation.len() as u32).to_be_bytes());
        hash.update(operation);
        Ok(hash.finalize().into())
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let operation = self.operation_bytes()?;
        if self.signature.is_empty() {
            return Err(Error::InvalidPriority);
        }
        if self.signature.len() > MAX_SIGNED_SIGNATURE_BYTES {
            return Err(Error::Oversize);
        }
        self.signing_digest()?;
        let mut out = Vec::with_capacity(
            4 + 2 + 32 + 32 + 8 + 8 + 4 + operation.len() + 2 + self.signature.len(),
        );
        out.extend_from_slice(&SIGNED_OP_MAGIC);
        out.extend_from_slice(&SIGNED_OP_VERSION.to_be_bytes());
        out.extend_from_slice(&self.network_id);
        out.extend_from_slice(&self.sender);
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&(operation.len() as u32).to_be_bytes());
        out.extend_from_slice(&operation);
        out.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.signature);
        if out.len() > MAX_SIGNED_OP_BYTES {
            return Err(Error::Oversize);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_SIGNED_OP_BYTES || bytes.len() < 4 + 2 + 32 + 32 + 8 + 8 + 4 + 2 {
            return Err(Error::Malformed);
        }
        let mut cursor = std::io::Cursor::new(bytes);
        if read_bytes::<4>(&mut cursor)? != SIGNED_OP_MAGIC {
            return Err(Error::Malformed);
        }
        if read_u16_leading(&mut cursor)? != SIGNED_OP_VERSION {
            return Err(Error::Malformed);
        }
        let network_id = read_bytes::<32>(&mut cursor)?;
        let sender = read_bytes::<32>(&mut cursor)?;
        let nonce = read_u64_be(&mut cursor)?;
        let expires_at = read_u64_be(&mut cursor)?;
        let operation_len = read_u32_be(&mut cursor)? as usize;
        if operation_len == 0 || operation_len > MAX_SIGNED_OP_BYTES {
            return Err(Error::Malformed);
        }
        let operation_bytes = read_vec(&mut cursor, operation_len)?;
        let operation = decode_signed_operation(&operation_bytes)?;
        let signature_len = read_u16_leading(&mut cursor)? as usize;
        if signature_len == 0 || signature_len > MAX_SIGNED_SIGNATURE_BYTES {
            return Err(Error::Malformed);
        }
        let signature = read_vec(&mut cursor, signature_len)?;
        if cursor.position() as usize != bytes.len() {
            return Err(Error::Malformed);
        }
        let signed = Self {
            network_id,
            sender,
            nonce,
            expires_at,
            operation,
            signature,
        };
        if signed.encode()?.as_slice() != bytes {
            return Err(Error::Malformed);
        }
        Ok(signed)
    }
}

fn decode_signed_operation(bytes: &[u8]) -> Result<QRunV06OrderBookOperation, Error> {
    let mut cursor = std::io::Cursor::new(bytes);
    let tag = read_bytes::<1>(&mut cursor)?[0];
    let operation = match tag {
        1 => QRunV06OrderBookOperation::CreatePair {
            base: read_bytes::<32>(&mut cursor)?,
            quote: read_bytes::<32>(&mut cursor)?,
            base_lot_atoms: read_u128_be(&mut cursor)?,
            quote_tick_atoms: read_u128_be(&mut cursor)?,
            max_price_ticks: read_u128_be(&mut cursor)?,
            max_quantity_lots: read_u128_be(&mut cursor)?,
            min_notional: read_u128_be(&mut cursor)?,
            maker_fee_bps: read_u16_leading(&mut cursor)?,
            taker_fee_bps: read_u16_leading(&mut cursor)?,
            fee_collector: read_bytes::<32>(&mut cursor)?,
        },
        2 => QRunV06OrderBookOperation::Deposit {
            asset: read_bytes::<32>(&mut cursor)?,
            amount: read_u128_be(&mut cursor)?,
        },
        3 => QRunV06OrderBookOperation::Withdraw {
            asset: read_bytes::<32>(&mut cursor)?,
            amount: read_u128_be(&mut cursor)?,
        },
        4 => {
            let pair = read_bytes::<32>(&mut cursor)?;
            let side = match read_bytes::<1>(&mut cursor)?[0] {
                1 => Side::Buy,
                2 => Side::Sell,
                _ => return Err(Error::Malformed),
            };
            let price_ticks = read_u128_be(&mut cursor)?;
            let quantity_lots = read_u128_be(&mut cursor)?;
            let tif = match read_bytes::<1>(&mut cursor)?[0] {
                1 => Tif::Gtc,
                2 => Tif::Ioc,
                3 => Tif::Fok,
                _ => return Err(Error::Malformed),
            };
            let expires_at_height = read_u64_be(&mut cursor)?;
            QRunV06OrderBookOperation::PlaceLimit {
                pair,
                side,
                price_ticks,
                quantity_lots,
                tif,
                expires_at_height,
            }
        }
        5 => QRunV06OrderBookOperation::Cancel {
            order_id: read_bytes::<32>(&mut cursor)?,
        },
        _ => return Err(Error::Malformed),
    };
    if cursor.position() as usize != bytes.len() {
        return Err(Error::Malformed);
    }
    Ok(operation)
}

fn read_bytes<const N: usize>(cursor: &mut std::io::Cursor<&[u8]>) -> Result<[u8; N], Error> {
    let mut output = [0u8; N];
    cursor
        .read_exact(&mut output)
        .map_err(|_| Error::Malformed)?;
    Ok(output)
}
fn read_vec(cursor: &mut std::io::Cursor<&[u8]>, length: usize) -> Result<Vec<u8>, Error> {
    let mut output = vec![0u8; length];
    cursor
        .read_exact(&mut output)
        .map_err(|_| Error::Malformed)?;
    Ok(output)
}
fn read_u16_leading(cursor: &mut std::io::Cursor<&[u8]>) -> Result<u16, Error> {
    Ok(u16::from_be_bytes(read_bytes(cursor)?))
}
fn read_u32_be(cursor: &mut std::io::Cursor<&[u8]>) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(read_bytes(cursor)?))
}
fn read_u64_be(cursor: &mut std::io::Cursor<&[u8]>) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(read_bytes(cursor)?))
}
fn read_u128_be(cursor: &mut std::io::Cursor<&[u8]>) -> Result<u128, Error> {
    Ok(u128::from_be_bytes(read_bytes(cursor)?))
}
fn tif_tag(tif: Tif) -> u8 {
    match tif {
        Tif::Gtc => 1,
        Tif::Ioc => 2,
        Tif::Fok => 3,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderBook {
    network: [u8; 32],
    pairs: BTreeMap<PairId, PairRules>,
    free: BTreeMap<(AssetId, AccountId), u128>,
    orders: BTreeMap<OrderId, Order>,
    fills: Vec<Fill>,
    max_pairs: usize,
    max_orders: usize,
    max_fills: usize,
}

impl OrderBook {
    pub fn new(
        network: [u8; 32],
        max_pairs: usize,
        max_orders: usize,
        max_fills: usize,
    ) -> Result<Self, Error> {
        if zero(&network) || max_pairs == 0 || max_orders == 0 || max_fills == 0 {
            return Err(Error::InvalidConfig);
        }
        Ok(Self {
            network,
            pairs: BTreeMap::new(),
            free: BTreeMap::new(),
            orders: BTreeMap::new(),
            fills: Vec::new(),
            max_pairs,
            max_orders,
            max_fills,
        })
    }

    pub fn pair_id(network: [u8; 32], base: AssetId, quote: AssetId) -> Result<PairId, Error> {
        if zero(&network) || zero(&base) || zero(&quote) || base == quote {
            return Err(Error::InvalidAsset);
        }
        let mut h = Sha256::new();
        h.update(PAIR_DOMAIN);
        h.update(network);
        h.update(base);
        h.update(quote);
        Ok(h.finalize().into())
    }

    pub fn register_pair(
        &mut self,
        base: AssetId,
        quote: AssetId,
        base_lot_atoms: u128,
        quote_tick_atoms: u128,
        max_price_ticks: u128,
        max_quantity_lots: u128,
        min_notional: u128,
        maker_fee_bps: u16,
        taker_fee_bps: u16,
        fee_collector: AccountId,
    ) -> Result<PairId, Error> {
        let id = Self::pair_id(self.network, base, quote)?;
        if self.pairs.contains_key(&id) {
            return Err(Error::DuplicatePair);
        }
        if self.pairs.len() >= self.max_pairs
            || base_lot_atoms == 0
            || quote_tick_atoms == 0
            || max_price_ticks == 0
            || max_quantity_lots == 0
            || min_notional == 0
            || zero(&fee_collector)
            || maker_fee_bps > taker_fee_bps
            || taker_fee_bps >= BPS as u16
        {
            return Err(Error::InvalidConfig);
        }
        self.pairs.insert(
            id,
            PairRules {
                id,
                base,
                quote,
                base_lot_atoms,
                quote_tick_atoms,
                max_price_ticks,
                max_quantity_lots,
                min_notional,
                maker_fee_bps,
                taker_fee_bps,
                fee_collector,
            },
        );
        self.verify().map(|()| id)
    }

    /// Test/genesis fixture only; QFP6 must source balances from its unified canonical asset ledger.
    pub fn credit_genesis(
        &mut self,
        asset: AssetId,
        account: AccountId,
        amount: u128,
    ) -> Result<(), Error> {
        if zero(&asset) {
            return Err(Error::InvalidAsset);
        }
        if zero(&account) || amount == 0 {
            return Err(Error::InvalidAccount);
        }
        self.credit(asset, account, amount)?;
        self.verify()
    }

    pub fn network_id(&self) -> [u8; 32] {
        self.network
    }

    pub fn balance(&self, asset: &AssetId, account: &AccountId) -> u128 {
        self.free.get(&(*asset, *account)).copied().unwrap_or(0)
    }

    /// Assets which have at least one canonical limit-order pair.
    pub fn registered_asset_ids(&self) -> Vec<AssetId> {
        let mut assets = std::collections::BTreeSet::new();
        for pair in self.pairs.values() {
            assets.insert(pair.base);
            assets.insert(pair.quote);
        }
        assets.into_iter().collect()
    }

    pub fn has_pair(&self, id: &PairId) -> bool {
        self.pairs.contains_key(id)
    }

    pub fn pair_rules(&self, id: &PairId) -> Option<&PairRules> {
        self.pairs.get(id)
    }

    /// Read-only deterministic iteration over all registered pair rules. Used by the
    /// canonical executor to fail closed on legacy snapshots containing an external
    /// quote pair without a persisted Q6QA authorization pin.
    pub fn pair_rules_iter(&self) -> impl Iterator<Item = &PairRules> {
        self.pairs.values()
    }

    /// Canonical free-balance projection used to validate the LOB vault backing.
    pub fn free_balance_entries(&self) -> Vec<(AssetId, AccountId, u128)> {
        self.free
            .iter()
            .map(|((asset, account), amount)| (*asset, *account, *amount))
            .collect()
    }

    /// Deposit from the separately authenticated canonical asset transition into the
    /// LOB sub-ledger. The surrounding QFB6 executor commits both views atomically.
    pub fn deposit_balance(
        &mut self,
        asset: AssetId,
        owner: AccountId,
        amount: u128,
    ) -> Result<(), Error> {
        if !self.registered_asset_ids().contains(&asset) {
            return Err(Error::InvalidAsset);
        }
        if zero(&owner) || amount == 0 {
            return Err(Error::InvalidAccount);
        }
        let mut next = self.clone();
        next.credit(asset, owner, amount)?;
        next.verify()?;
        *self = next;
        Ok(())
    }

    /// Withdraw only spendable LOB balance; order escrow cannot be withdrawn.
    pub fn withdraw_balance(
        &mut self,
        asset: AssetId,
        owner: AccountId,
        amount: u128,
    ) -> Result<(), Error> {
        if !self.registered_asset_ids().contains(&asset) {
            return Err(Error::InvalidAsset);
        }
        if zero(&owner) || amount == 0 {
            return Err(Error::InvalidAccount);
        }
        let mut next = self.clone();
        next.debit(asset, owner, amount)?;
        next.verify()?;
        *self = next;
        Ok(())
    }

    /// Aggregate resting-order escrow for one asset across every configured pair.
    pub fn total_escrow_for_asset(&self, asset: AssetId) -> Result<u128, Error> {
        self.orders.values().try_fold(0u128, |sum, order| {
            let pair = self.pairs.get(&order.pair).ok_or(Error::Invariant)?;
            let locked_asset = if order.side == Side::Buy {
                pair.quote
            } else {
                pair.base
            };
            if locked_asset == asset {
                sum.checked_add(order.locked_atoms).ok_or(Error::Overflow)
            } else {
                Ok(sum)
            }
        })
    }

    pub fn order(&self, id: &OrderId) -> Option<&Order> {
        self.orders.get(id)
    }
    pub fn orders(&self) -> impl Iterator<Item = &Order> {
        self.orders.values()
    }
    pub fn fills(&self) -> &[Fill] {
        &self.fills
    }

    pub fn escrow(&self, asset: AssetId, account: AccountId) -> Result<u128, Error> {
        self.orders
            .values()
            .filter(|o| o.owner == account)
            .try_fold(0u128, |sum, o| {
                let p = self.pairs.get(&o.pair).ok_or(Error::Invariant)?;
                let locked_asset = match o.side {
                    Side::Buy => p.quote,
                    Side::Sell => p.base,
                };
                if locked_asset == asset {
                    sum.checked_add(o.locked_atoms).ok_or(Error::Overflow)
                } else {
                    Ok(sum)
                }
            })
    }

    /// Total asset units across spendable balances and order escrow.
    pub fn total_asset_balance(&self, asset: AssetId) -> Result<u128, Error> {
        let free = self
            .free
            .iter()
            .filter(|((key, _), _)| *key == asset)
            .try_fold(0u128, |sum, (_, amount)| {
                sum.checked_add(*amount).ok_or(Error::Overflow)
            })?;
        self.orders.values().try_fold(free, |sum, order| {
            let pair = self.pairs.get(&order.pair).ok_or(Error::Invariant)?;
            let locked_asset = if order.side == Side::Buy {
                pair.quote
            } else {
                pair.base
            };
            if locked_asset == asset {
                sum.checked_add(order.locked_atoms).ok_or(Error::Overflow)
            } else {
                Ok(sum)
            }
        })
    }

    /// Transactional clone/apply/verify: every error leaves the previous state unchanged.
    pub fn place(&mut self, request: PlaceLimit) -> Result<PlaceResult, Error> {
        let mut next = self.clone();
        let result = next.place_inner(request)?;
        next.verify()?;
        *self = next;
        Ok(result)
    }

    fn place_inner(&mut self, r: PlaceLimit) -> Result<PlaceResult, Error> {
        let p = self
            .pairs
            .get(&r.pair)
            .cloned()
            .ok_or(Error::PairNotFound)?;
        if zero(&r.owner) || r.owner == p.fee_collector {
            return Err(Error::InvalidAccount);
        }
        if r.price_ticks == 0 || r.price_ticks > p.max_price_ticks {
            return Err(Error::InvalidPrice);
        }
        if r.quantity_lots == 0 || r.quantity_lots > p.max_quantity_lots {
            return Err(Error::InvalidQuantity);
        }
        if r.expires_at_height <= r.priority.height {
            return Err(Error::InvalidExpiry);
        }
        if r.priority.height == 0
            || zero(&r.transaction_id)
            || r.priority.op_index != r.operation_index
        {
            return Err(Error::InvalidPriority);
        }
        // The block executor must deterministically expire all orders due at this height
        // before applying user market operations. Never match a stale order by omission.
        if self
            .orders
            .values()
            .any(|order| order.expires_at_height <= r.priority.height)
        {
            return Err(Error::ExpiryNotProcessed);
        }
        let id = order_id(self.network, r.transaction_id, r.operation_index);
        if self.orders.contains_key(&id)
            || self
                .fills
                .iter()
                .any(|f| f.taker_order == id || f.maker_order == id)
        {
            return Err(Error::DuplicateOrder);
        }
        let notional = quote(&p, r.price_ticks, r.quantity_lots)?;
        if notional < p.min_notional {
            return Err(Error::InvalidQuantity);
        }
        let lock = match r.side {
            Side::Buy => notional
                .checked_add(fee(notional, p.taker_fee_bps)?)
                .ok_or(Error::Overflow)?,
            Side::Sell => base(&p, r.quantity_lots)?,
        };
        let asset = match r.side {
            Side::Buy => p.quote,
            Side::Sell => p.base,
        };
        self.debit(asset, r.owner, lock)?;
        let mut taker = Order {
            id,
            pair: r.pair,
            owner: r.owner,
            side: r.side,
            price_ticks: r.price_ticks,
            original_lots: r.quantity_lots,
            remaining_lots: r.quantity_lots,
            priority: r.priority,
            expires_at_height: r.expires_at_height,
            locked_atoms: lock,
        };

        let makers = self.crossing(&taker);
        if r.tif == Tif::Fok {
            let available = makers.iter().try_fold(0u128, |sum, m| {
                if m.owner == taker.owner {
                    return Err(Error::SelfTrade);
                }
                sum.checked_add(m.remaining_lots).ok_or(Error::Overflow)
            })?;
            if available < taker.remaining_lots {
                return Err(Error::InsufficientLiquidity);
            }
        }

        let mut ids = Vec::new();
        for (i, maker) in makers.iter().enumerate() {
            if taker.remaining_lots == 0 {
                break;
            }
            if maker.owner == taker.owner {
                return Err(Error::SelfTrade);
            }
            let qty = taker.remaining_lots.min(maker.remaining_lots);
            let f = self.match_one(
                &mut taker,
                maker.id,
                qty,
                u32::try_from(i).map_err(|_| Error::Overflow)?,
                r.transaction_id,
            )?;
            ids.push(f.id);
            self.fills.push(f);
            if self.fills.len() > self.max_fills {
                return Err(Error::TooManyFills);
            }
        }

        if taker.remaining_lots > 0 && r.tif == Tif::Gtc {
            if self.orders.len() >= self.max_orders {
                return Err(Error::TooManyOrders);
            }
            self.orders.insert(id, taker.clone());
        } else {
            self.release(&taker)?;
            if r.tif == Tif::Fok && taker.remaining_lots != 0 {
                return Err(Error::InsufficientLiquidity);
            }
        }
        Ok(PlaceResult {
            order_id: id,
            filled_lots: r.quantity_lots - taker.remaining_lots,
            remaining_lots: taker.remaining_lots,
            fill_ids: ids,
        })
    }

    fn crossing(&self, taker: &Order) -> Vec<Order> {
        let mut makers: Vec<Order> = self
            .orders
            .values()
            .filter(|m| {
                m.pair == taker.pair
                    && m.side != taker.side
                    && match taker.side {
                        Side::Buy => m.price_ticks <= taker.price_ticks,
                        Side::Sell => m.price_ticks >= taker.price_ticks,
                    }
            })
            .cloned()
            .collect();
        makers.sort_by(|a, b| {
            let by_price = match taker.side {
                Side::Buy => a.price_ticks.cmp(&b.price_ticks),
                Side::Sell => b.price_ticks.cmp(&a.price_ticks),
            };
            by_price
                .then(a.priority.cmp(&b.priority))
                .then(a.id.cmp(&b.id))
        });
        makers
    }

    fn match_one(
        &mut self,
        taker: &mut Order,
        maker_id: OrderId,
        qty: u128,
        match_index: u32,
        txid: [u8; 32],
    ) -> Result<Fill, Error> {
        let mut maker = self
            .orders
            .get(&maker_id)
            .cloned()
            .ok_or(Error::OrderNotFound)?;
        let p = self
            .pairs
            .get(&taker.pair)
            .cloned()
            .ok_or(Error::PairNotFound)?;
        if maker.owner == taker.owner || maker.side == taker.side {
            return Err(Error::SelfTrade);
        }
        let base_amt = base(&p, qty)?;
        let quote_amt = quote(&p, maker.price_ticks, qty)?;
        let buyer_maker = maker.side == Side::Buy;
        let seller_maker = maker.side == Side::Sell;
        let buyer_fee = fee(
            quote_amt,
            if buyer_maker {
                p.maker_fee_bps
            } else {
                p.taker_fee_bps
            },
        )?;
        let seller_fee = fee(
            quote_amt,
            if seller_maker {
                p.maker_fee_bps
            } else {
                p.taker_fee_bps
            },
        )?;
        let buyer_cost = quote_amt.checked_add(buyer_fee).ok_or(Error::Overflow)?;
        let seller_net = quote_amt.checked_sub(seller_fee).ok_or(Error::Underflow)?;

        if taker.side == Side::Buy {
            taker.locked_atoms = taker
                .locked_atoms
                .checked_sub(buyer_cost)
                .ok_or(Error::Underflow)?;
            maker.locked_atoms = maker
                .locked_atoms
                .checked_sub(base_amt)
                .ok_or(Error::Underflow)?;
        } else {
            taker.locked_atoms = taker
                .locked_atoms
                .checked_sub(base_amt)
                .ok_or(Error::Underflow)?;
            maker.locked_atoms = maker
                .locked_atoms
                .checked_sub(buyer_cost)
                .ok_or(Error::Underflow)?;
        }
        let (buyer, seller) = match taker.side {
            Side::Buy => (taker.owner, maker.owner),
            Side::Sell => (maker.owner, taker.owner),
        };
        self.credit(p.base, buyer, base_amt)?;
        self.credit(p.quote, seller, seller_net)?;
        self.credit(
            p.quote,
            p.fee_collector,
            buyer_fee.checked_add(seller_fee).ok_or(Error::Overflow)?,
        )?;
        taker.remaining_lots = taker
            .remaining_lots
            .checked_sub(qty)
            .ok_or(Error::Underflow)?;
        maker.remaining_lots = maker
            .remaining_lots
            .checked_sub(qty)
            .ok_or(Error::Underflow)?;
        let fid = fill_id(self.network, txid, maker_id, taker.id, match_index);
        let fill = Fill {
            id: fid,
            pair: taker.pair,
            maker_order: maker_id,
            taker_order: taker.id,
            buyer,
            seller,
            price_ticks: maker.price_ticks,
            quantity_lots: qty,
            base_atoms: base_amt,
            quote_atoms: quote_amt,
            buyer_fee,
            seller_fee,
            match_index,
        };
        if maker.remaining_lots == 0 {
            self.orders.remove(&maker_id);
            self.release(&maker)?;
        } else {
            self.orders.insert(maker_id, maker);
        }
        Ok(fill)
    }

    pub fn cancel(&mut self, id: OrderId, owner: AccountId) -> Result<u128, Error> {
        let mut next = self.clone();
        let o = next.orders.get(&id).cloned().ok_or(Error::OrderNotFound)?;
        if o.owner != owner {
            return Err(Error::NotOwner);
        }
        next.orders.remove(&id);
        next.release(&o)?;
        next.verify()?;
        *self = next;
        Ok(o.locked_atoms)
    }

    pub fn expire(&mut self, height: u64) -> Result<Vec<OrderId>, Error> {
        if height == 0 {
            return Err(Error::InvalidExpiry);
        }
        let mut next = self.clone();
        let expired: Vec<Order> = next
            .orders
            .values()
            .filter(|o| o.expires_at_height <= height)
            .cloned()
            .collect();
        let mut ids = Vec::with_capacity(expired.len());
        for o in expired {
            next.orders.remove(&o.id);
            next.release(&o)?;
            ids.push(o.id);
        }
        next.verify()?;
        *self = next;
        Ok(ids)
    }

    fn debit(&mut self, asset: AssetId, owner: AccountId, amount: u128) -> Result<(), Error> {
        let left = self
            .balance(&asset, &owner)
            .checked_sub(amount)
            .ok_or(Error::InsufficientBalance)?;
        if left == 0 {
            self.free.remove(&(asset, owner));
        } else {
            self.free.insert((asset, owner), left);
        }
        Ok(())
    }
    fn credit(&mut self, asset: AssetId, owner: AccountId, amount: u128) -> Result<(), Error> {
        if amount == 0 {
            return Ok(());
        }
        let value = self
            .balance(&asset, &owner)
            .checked_add(amount)
            .ok_or(Error::Overflow)?;
        self.free.insert((asset, owner), value);
        Ok(())
    }
    fn release(&mut self, o: &Order) -> Result<(), Error> {
        let p = self.pairs.get(&o.pair).ok_or(Error::PairNotFound)?;
        self.credit(
            if o.side == Side::Buy { p.quote } else { p.base },
            o.owner,
            o.locked_atoms,
        )
    }
    fn minimum_lock(&self, o: &Order, p: &PairRules) -> Result<u128, Error> {
        if o.side == Side::Sell {
            base(p, o.remaining_lots)
        } else {
            let n = quote(p, o.price_ticks, o.remaining_lots)?;
            n.checked_add(fee(n, p.taker_fee_bps)?)
                .ok_or(Error::Overflow)
        }
    }

    pub fn verify(&self) -> Result<(), Error> {
        if zero(&self.network)
            || self.pairs.len() > self.max_pairs
            || self.orders.len() > self.max_orders
            || self.fills.len() > self.max_fills
        {
            return Err(Error::Invariant);
        }
        for ((asset, account), amount) in &self.free {
            if zero(asset) || zero(account) || *amount == 0 {
                return Err(Error::Invariant);
            }
        }
        for (id, p) in &self.pairs {
            if id != &p.id
                || Self::pair_id(self.network, p.base, p.quote)? != *id
                || p.base_lot_atoms == 0
                || p.quote_tick_atoms == 0
                || p.max_price_ticks == 0
                || p.max_quantity_lots == 0
                || p.min_notional == 0
                || zero(&p.fee_collector)
                || p.maker_fee_bps > p.taker_fee_bps
                || p.taker_fee_bps >= BPS as u16
            {
                return Err(Error::Invariant);
            }
        }
        for (id, o) in &self.orders {
            let p = self.pairs.get(&o.pair).ok_or(Error::Invariant)?;
            if *id != o.id
                || zero(&o.owner)
                || o.remaining_lots == 0
                || o.remaining_lots > o.original_lots
                || o.price_ticks == 0
                || o.price_ticks > p.max_price_ticks
                || o.original_lots > p.max_quantity_lots
                || o.expires_at_height <= o.priority.height
                || o.priority.height == 0
                || o.locked_atoms < self.minimum_lock(o, p)?
            {
                return Err(Error::Invariant);
            }
        }
        for f in &self.fills {
            if zero(&f.id)
                || zero(&f.buyer)
                || zero(&f.seller)
                || f.buyer == f.seller
                || f.quantity_lots == 0
            {
                return Err(Error::Invariant);
            }
        }
        Ok(())
    }

    /// Encode the complete order book, including historical fills, with strict map ordering.
    /// The checksum is corruption detection only; it does not prevent rollback.
    pub fn encode_snapshot(&self) -> Result<Vec<u8>, Error> {
        self.verify()?;
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&SNAPSHOT_MAGIC);
        out.extend_from_slice(&SNAPSHOT_VERSION.to_be_bytes());
        out.extend_from_slice(&self.network);
        snapshot_put_count(&mut out, self.max_pairs)?;
        snapshot_put_count(&mut out, self.max_orders)?;
        snapshot_put_count(&mut out, self.max_fills)?;
        snapshot_put_count(&mut out, self.pairs.len())?;
        for (id, pair) in &self.pairs {
            out.extend_from_slice(id);
            out.extend_from_slice(&pair.base);
            out.extend_from_slice(&pair.quote);
            out.extend_from_slice(&pair.base_lot_atoms.to_be_bytes());
            out.extend_from_slice(&pair.quote_tick_atoms.to_be_bytes());
            out.extend_from_slice(&pair.max_price_ticks.to_be_bytes());
            out.extend_from_slice(&pair.max_quantity_lots.to_be_bytes());
            out.extend_from_slice(&pair.min_notional.to_be_bytes());
            out.extend_from_slice(&pair.maker_fee_bps.to_be_bytes());
            out.extend_from_slice(&pair.taker_fee_bps.to_be_bytes());
            out.extend_from_slice(&pair.fee_collector);
            snapshot_check_size(out.len())?;
        }
        snapshot_put_count(&mut out, self.free.len())?;
        for ((asset, account), amount) in &self.free {
            out.extend_from_slice(asset);
            out.extend_from_slice(account);
            out.extend_from_slice(&amount.to_be_bytes());
            snapshot_check_size(out.len())?;
        }
        snapshot_put_count(&mut out, self.orders.len())?;
        for (id, order) in &self.orders {
            out.extend_from_slice(id);
            out.extend_from_slice(&order.pair);
            out.extend_from_slice(&order.owner);
            out.push(side_tag(order.side));
            out.extend_from_slice(&order.price_ticks.to_be_bytes());
            out.extend_from_slice(&order.original_lots.to_be_bytes());
            out.extend_from_slice(&order.remaining_lots.to_be_bytes());
            out.extend_from_slice(&order.priority.height.to_be_bytes());
            out.extend_from_slice(&order.priority.tx_index.to_be_bytes());
            out.extend_from_slice(&order.priority.op_index.to_be_bytes());
            out.extend_from_slice(&order.expires_at_height.to_be_bytes());
            out.extend_from_slice(&order.locked_atoms.to_be_bytes());
            snapshot_check_size(out.len())?;
        }
        snapshot_put_count(&mut out, self.fills.len())?;
        for fill in &self.fills {
            out.extend_from_slice(&fill.id);
            out.extend_from_slice(&fill.pair);
            out.extend_from_slice(&fill.maker_order);
            out.extend_from_slice(&fill.taker_order);
            out.extend_from_slice(&fill.buyer);
            out.extend_from_slice(&fill.seller);
            out.extend_from_slice(&fill.price_ticks.to_be_bytes());
            out.extend_from_slice(&fill.quantity_lots.to_be_bytes());
            out.extend_from_slice(&fill.base_atoms.to_be_bytes());
            out.extend_from_slice(&fill.quote_atoms.to_be_bytes());
            out.extend_from_slice(&fill.buyer_fee.to_be_bytes());
            out.extend_from_slice(&fill.seller_fee.to_be_bytes());
            out.extend_from_slice(&fill.match_index.to_be_bytes());
            snapshot_check_size(out.len())?;
        }
        snapshot_check_size(out.len())?;
        let mut checksum = Sha256::new();
        checksum.update(SNAPSHOT_CHECKSUM_DOMAIN);
        checksum.update(&out);
        out.extend_from_slice(&checksum.finalize());
        Ok(out)
    }

    /// Restore an exact canonical OrderBook state and validate its pair/order/fill invariants.
    pub fn decode_snapshot(bytes: &[u8], expected_network: &[u8; 32]) -> Result<Self, Error> {
        if bytes.len() > MAX_QRUN_V06_ORDERBOOK_SNAPSHOT_BYTES {
            return Err(Error::SnapshotOversize);
        }
        if zero(expected_network) || bytes.len() < 4 + 2 + 32 + 12 + 4 + 4 + 4 + 4 + 32 {
            return Err(Error::SnapshotMalformed);
        }
        let body_len = bytes.len() - 32;
        let mut checksum = Sha256::new();
        checksum.update(SNAPSHOT_CHECKSUM_DOMAIN);
        checksum.update(&bytes[..body_len]);
        if checksum.finalize().as_slice() != &bytes[body_len..] {
            return Err(Error::SnapshotChecksumMismatch);
        }

        let body = &bytes[..body_len];
        let mut cursor = std::io::Cursor::new(body);
        if read_bytes::<4>(&mut cursor)? != SNAPSHOT_MAGIC
            || read_u16_leading(&mut cursor)? != SNAPSHOT_VERSION
        {
            return Err(Error::SnapshotMalformed);
        }
        let network = read_bytes::<32>(&mut cursor)?;
        if &network != expected_network {
            return Err(Error::WrongNetwork);
        }
        let max_pairs = snapshot_read_count(&mut cursor)?;
        let max_orders = snapshot_read_count(&mut cursor)?;
        let max_fills = snapshot_read_count(&mut cursor)?;
        if max_pairs == 0
            || max_orders == 0
            || max_fills == 0
            || max_pairs > MAX_ORDERBOOK_SNAPSHOT_ENTRIES
            || max_orders > MAX_ORDERBOOK_SNAPSHOT_ENTRIES
            || max_fills > MAX_ORDERBOOK_SNAPSHOT_ENTRIES
        {
            return Err(Error::SnapshotMalformed);
        }

        let pair_count = snapshot_read_count(&mut cursor)?;
        if pair_count > max_pairs {
            return Err(Error::SnapshotMalformed);
        }
        let mut pairs = BTreeMap::new();
        let mut previous_pair: Option<PairId> = None;
        for _ in 0..pair_count {
            let id = read_bytes::<32>(&mut cursor)?;
            if previous_pair.is_some_and(|previous| previous >= id) {
                return Err(Error::SnapshotNonCanonical);
            }
            previous_pair = Some(id);
            let pair = PairRules {
                id,
                base: read_bytes::<32>(&mut cursor)?,
                quote: read_bytes::<32>(&mut cursor)?,
                base_lot_atoms: read_u128_be(&mut cursor)?,
                quote_tick_atoms: read_u128_be(&mut cursor)?,
                max_price_ticks: read_u128_be(&mut cursor)?,
                max_quantity_lots: read_u128_be(&mut cursor)?,
                min_notional: read_u128_be(&mut cursor)?,
                maker_fee_bps: read_u16_leading(&mut cursor)?,
                taker_fee_bps: read_u16_leading(&mut cursor)?,
                fee_collector: read_bytes::<32>(&mut cursor)?,
            };
            pairs.insert(id, pair);
        }

        let free_count = snapshot_read_count(&mut cursor)?;
        if free_count > MAX_ORDERBOOK_SNAPSHOT_ENTRIES {
            return Err(Error::SnapshotMalformed);
        }
        let mut free = BTreeMap::new();
        let mut previous_free: Option<(AssetId, AccountId)> = None;
        for _ in 0..free_count {
            let asset = read_bytes::<32>(&mut cursor)?;
            let account = read_bytes::<32>(&mut cursor)?;
            let key = (asset, account);
            if previous_free.is_some_and(|previous| previous >= key) {
                return Err(Error::SnapshotNonCanonical);
            }
            previous_free = Some(key);
            let amount = read_u128_be(&mut cursor)?;
            free.insert(key, amount);
        }

        let order_count = snapshot_read_count(&mut cursor)?;
        if order_count > max_orders {
            return Err(Error::SnapshotMalformed);
        }
        let mut orders = BTreeMap::new();
        let mut previous_order: Option<OrderId> = None;
        for _ in 0..order_count {
            let id = read_bytes::<32>(&mut cursor)?;
            if previous_order.is_some_and(|previous| previous >= id) {
                return Err(Error::SnapshotNonCanonical);
            }
            previous_order = Some(id);
            let pair = read_bytes::<32>(&mut cursor)?;
            let owner = read_bytes::<32>(&mut cursor)?;
            let side = match read_bytes::<1>(&mut cursor)?[0] {
                1 => Side::Buy,
                2 => Side::Sell,
                _ => return Err(Error::SnapshotMalformed),
            };
            let order = Order {
                id,
                pair,
                owner,
                side,
                price_ticks: read_u128_be(&mut cursor)?,
                original_lots: read_u128_be(&mut cursor)?,
                remaining_lots: read_u128_be(&mut cursor)?,
                priority: Priority {
                    height: read_u64_be(&mut cursor)?,
                    tx_index: read_u32_be(&mut cursor)?,
                    op_index: read_u32_be(&mut cursor)?,
                },
                expires_at_height: read_u64_be(&mut cursor)?,
                locked_atoms: read_u128_be(&mut cursor)?,
            };
            orders.insert(id, order);
        }

        let fill_count = snapshot_read_count(&mut cursor)?;
        if fill_count > max_fills {
            return Err(Error::SnapshotMalformed);
        }
        let mut fills = Vec::with_capacity(fill_count);
        let mut fill_ids = std::collections::BTreeSet::new();
        for _ in 0..fill_count {
            let fill = Fill {
                id: read_bytes::<32>(&mut cursor)?,
                pair: read_bytes::<32>(&mut cursor)?,
                maker_order: read_bytes::<32>(&mut cursor)?,
                taker_order: read_bytes::<32>(&mut cursor)?,
                buyer: read_bytes::<32>(&mut cursor)?,
                seller: read_bytes::<32>(&mut cursor)?,
                price_ticks: read_u128_be(&mut cursor)?,
                quantity_lots: read_u128_be(&mut cursor)?,
                base_atoms: read_u128_be(&mut cursor)?,
                quote_atoms: read_u128_be(&mut cursor)?,
                buyer_fee: read_u128_be(&mut cursor)?,
                seller_fee: read_u128_be(&mut cursor)?,
                match_index: read_u32_be(&mut cursor)?,
            };
            if !fill_ids.insert(fill.id) {
                return Err(Error::SnapshotNonCanonical);
            }
            fills.push(fill);
        }
        if cursor.position() as usize != body.len() {
            return Err(Error::SnapshotNonCanonical);
        }

        let restored = Self {
            network,
            pairs,
            free,
            orders,
            fills,
            max_pairs,
            max_orders,
            max_fills,
        };
        restored.verify()?;
        if restored.encode_snapshot()?.as_slice() != bytes {
            return Err(Error::SnapshotNonCanonical);
        }
        Ok(restored)
    }

    pub fn state_root(&self) -> Result<[u8; 32], Error> {
        self.verify()?;
        let mut h = Sha256::new();
        h.update(ROOT_DOMAIN);
        h.update(self.network);
        h.update((self.max_pairs as u64).to_be_bytes());
        h.update((self.max_orders as u64).to_be_bytes());
        h.update((self.max_fills as u64).to_be_bytes());
        h.update((self.pairs.len() as u64).to_be_bytes());
        for (id, p) in &self.pairs {
            h.update(id);
            h.update(p.base);
            h.update(p.quote);
            h.update(p.base_lot_atoms.to_be_bytes());
            h.update(p.quote_tick_atoms.to_be_bytes());
            h.update(p.max_price_ticks.to_be_bytes());
            h.update(p.max_quantity_lots.to_be_bytes());
            h.update(p.min_notional.to_be_bytes());
            h.update(p.maker_fee_bps.to_be_bytes());
            h.update(p.taker_fee_bps.to_be_bytes());
            h.update(p.fee_collector);
        }
        h.update((self.free.len() as u64).to_be_bytes());
        for ((asset, owner), balance) in &self.free {
            h.update(asset);
            h.update(owner);
            h.update(balance.to_be_bytes());
        }
        h.update((self.orders.len() as u64).to_be_bytes());
        for (id, o) in &self.orders {
            h.update(id);
            h.update(o.pair);
            h.update(o.owner);
            h.update([side_tag(o.side)]);
            h.update(o.price_ticks.to_be_bytes());
            h.update(o.original_lots.to_be_bytes());
            h.update(o.remaining_lots.to_be_bytes());
            h.update(o.priority.height.to_be_bytes());
            h.update(o.priority.tx_index.to_be_bytes());
            h.update(o.priority.op_index.to_be_bytes());
            h.update(o.expires_at_height.to_be_bytes());
            h.update(o.locked_atoms.to_be_bytes());
        }
        h.update((self.fills.len() as u64).to_be_bytes());
        for f in &self.fills {
            h.update(f.id);
            h.update(f.pair);
            h.update(f.maker_order);
            h.update(f.taker_order);
            h.update(f.buyer);
            h.update(f.seller);
            h.update(f.price_ticks.to_be_bytes());
            h.update(f.quantity_lots.to_be_bytes());
            h.update(f.base_atoms.to_be_bytes());
            h.update(f.quote_atoms.to_be_bytes());
            h.update(f.buyer_fee.to_be_bytes());
            h.update(f.seller_fee.to_be_bytes());
            h.update(f.match_index.to_be_bytes());
        }
        Ok(h.finalize().into())
    }
}

fn snapshot_put_count(out: &mut Vec<u8>, count: usize) -> Result<(), Error> {
    let count = u32::try_from(count).map_err(|_| Error::SnapshotOversize)?;
    out.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

fn snapshot_read_count(cursor: &mut std::io::Cursor<&[u8]>) -> Result<usize, Error> {
    let count = read_u32_be(cursor)? as usize;
    if count > MAX_ORDERBOOK_SNAPSHOT_ENTRIES {
        return Err(Error::SnapshotMalformed);
    }
    Ok(count)
}

fn snapshot_check_size(length: usize) -> Result<(), Error> {
    if length.saturating_add(32) > MAX_QRUN_V06_ORDERBOOK_SNAPSHOT_BYTES {
        Err(Error::SnapshotOversize)
    } else {
        Ok(())
    }
}

fn quote(p: &PairRules, price: u128, lots: u128) -> Result<u128, Error> {
    price
        .checked_mul(p.quote_tick_atoms)
        .and_then(|x| x.checked_mul(lots))
        .ok_or(Error::Overflow)
}
fn base(p: &PairRules, lots: u128) -> Result<u128, Error> {
    p.base_lot_atoms.checked_mul(lots).ok_or(Error::Overflow)
}
fn fee(notional: u128, bps: u16) -> Result<u128, Error> {
    let b = bps as u128;
    if b >= BPS {
        return Err(Error::InvalidConfig);
    }
    let a = (notional / BPS).checked_mul(b).ok_or(Error::Overflow)?;
    let r = (notional % BPS).checked_mul(b).ok_or(Error::Overflow)?;
    a.checked_add(r.checked_add(BPS - 1).ok_or(Error::Overflow)? / BPS)
        .ok_or(Error::Overflow)
}
fn order_id(network: [u8; 32], tx: [u8; 32], op: u32) -> OrderId {
    let mut h = Sha256::new();
    h.update(ORDER_DOMAIN);
    h.update(network);
    h.update(tx);
    h.update(op.to_be_bytes());
    h.finalize().into()
}
fn fill_id(network: [u8; 32], tx: [u8; 32], maker: OrderId, taker: OrderId, index: u32) -> FillId {
    let mut h = Sha256::new();
    h.update(FILL_DOMAIN);
    h.update(network);
    h.update(tx);
    h.update(maker);
    h.update(taker);
    h.update(index.to_be_bytes());
    h.finalize().into()
}
fn side_tag(s: Side) -> u8 {
    if s == Side::Buy {
        1
    } else {
        2
    }
}
fn zero(x: &[u8; 32]) -> bool {
    x.iter().all(|b| *b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    const N: [u8; 32] = [0x71; 32];
    const B: AssetId = [0x72; 32];
    const Q: AssetId = [0x73; 32];
    const FEES: AccountId = [0x74; 32];
    fn acct(x: u8) -> AccountId {
        [x; 32]
    }
    fn setup() -> (OrderBook, PairId) {
        let mut s = OrderBook::new(N, 8, 128, 512).unwrap();
        let p = s
            .register_pair(B, Q, 100, 100, 1000, 1000, 100, 10, 20, FEES)
            .unwrap();
        (s, p)
    }
    fn submit(
        s: &mut OrderBook,
        p: PairId,
        owner: AccountId,
        side: Side,
        price: u128,
        lots: u128,
        tif: Tif,
        height: u64,
        tx: u8,
    ) -> PlaceResult {
        s.place(PlaceLimit {
            pair: p,
            owner,
            side,
            price_ticks: price,
            quantity_lots: lots,
            tif,
            expires_at_height: height + 100,
            priority: Priority {
                height,
                tx_index: 0,
                op_index: 0,
            },
            transaction_id: [tx; 32],
            operation_index: 0,
        })
        .unwrap()
    }

    #[test]
    fn orderbook_snapshot_roundtrips_open_escrow_balances_and_fill_history() {
        let (mut book, pair) = setup();
        let buyer = acct(1);
        let seller = acct(2);
        book.credit_genesis(B, seller, 300).unwrap();
        book.credit_genesis(Q, buyer, 10_000).unwrap();
        let ask = submit(&mut book, pair, seller, Side::Sell, 2, 2, Tif::Gtc, 1, 0x91);
        let bid = submit(&mut book, pair, buyer, Side::Buy, 3, 1, Tif::Ioc, 2, 0x92);
        assert_eq!(bid.filled_lots, 1);
        assert_eq!(book.fills().len(), 1);
        assert_eq!(book.order(&ask.order_id).unwrap().remaining_lots, 1);

        let root = book.state_root().unwrap();
        let encoded = book.encode_snapshot().unwrap();
        let restored = OrderBook::decode_snapshot(&encoded, &N).unwrap();
        assert_eq!(restored, book);
        assert_eq!(restored.state_root().unwrap(), root);
        assert_eq!(restored.fills(), book.fills());
        assert_eq!(restored.order(&ask.order_id).unwrap().locked_atoms, 100);

        let mut corrupt = encoded.clone();
        let index = corrupt.len() / 2;
        corrupt[index] ^= 1;
        assert_eq!(
            OrderBook::decode_snapshot(&corrupt, &N),
            Err(Error::SnapshotChecksumMismatch)
        );
        assert_eq!(
            OrderBook::decode_snapshot(&encoded, &[0x75; 32]),
            Err(Error::WrongNetwork)
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            OrderBook::decode_snapshot(&trailing, &N),
            Err(Error::SnapshotChecksumMismatch)
        );
    }

    #[test]
    fn maker_price_fees_and_balance_conservation() {
        let (mut s, p) = setup();
        let buyer = acct(1);
        let seller = acct(2);
        s.credit_genesis(B, seller, 300).unwrap();
        s.credit_genesis(Q, buyer, 10_000).unwrap();
        let ask = submit(&mut s, p, seller, Side::Sell, 2, 3, Tif::Gtc, 1, 0x11);
        let bid = submit(&mut s, p, buyer, Side::Buy, 3, 3, Tif::Ioc, 2, 0x12);
        assert_eq!((bid.filled_lots, bid.remaining_lots), (3, 0));
        let f = &s.fills()[0];
        assert_eq!(
            (f.price_ticks, f.quote_atoms, f.buyer_fee, f.seller_fee),
            (2, 600, 2, 1)
        );
        assert_eq!(s.balance(&B, &buyer), 300);
        assert_eq!(s.balance(&Q, &seller), 599);
        assert_eq!(s.balance(&Q, &FEES), 3);
        assert_eq!(s.balance(&Q, &buyer), 9398);
        assert_eq!(s.total_asset_balance(B).unwrap(), 300);
        assert_eq!(s.total_asset_balance(Q).unwrap(), 10_000);
        assert!(s.order(&ask.order_id).is_none());
        s.verify().unwrap();
    }

    #[test]
    fn price_then_canonical_time_priority() {
        let (mut s, p) = setup();
        let buyer = acct(1);
        let a = acct(2);
        let b = acct(3);
        s.credit_genesis(B, a, 100).unwrap();
        s.credit_genesis(B, b, 100).unwrap();
        s.credit_genesis(Q, buyer, 50_000).unwrap();
        let old = submit(&mut s, p, a, Side::Sell, 4, 1, Tif::Gtc, 1, 0x21);
        let best = submit(&mut s, p, b, Side::Sell, 3, 1, Tif::Gtc, 2, 0x22);
        submit(&mut s, p, buyer, Side::Buy, 5, 2, Tif::Ioc, 3, 0x23);
        assert_eq!(s.fills()[0].maker_order, best.order_id);
        assert_eq!(s.fills()[0].price_ticks, 3);
        assert_eq!(s.fills()[1].maker_order, old.order_id);
        assert_eq!(s.fills()[1].price_ticks, 4);
    }

    #[test]
    fn fok_insufficient_liquidity_is_atomic() {
        let (mut s, p) = setup();
        let buyer = acct(1);
        let seller = acct(2);
        s.credit_genesis(B, seller, 100).unwrap();
        s.credit_genesis(Q, buyer, 10_000).unwrap();
        submit(&mut s, p, seller, Side::Sell, 2, 1, Tif::Gtc, 1, 0x31);
        let root = s.state_root().unwrap();
        let result = s.place(PlaceLimit {
            pair: p,
            owner: buyer,
            side: Side::Buy,
            price_ticks: 3,
            quantity_lots: 2,
            tif: Tif::Fok,
            expires_at_height: 200,
            priority: Priority {
                height: 2,
                tx_index: 0,
                op_index: 0,
            },
            transaction_id: [0x32; 32],
            operation_index: 0,
        });
        assert_eq!(result, Err(Error::InsufficientLiquidity));
        assert_eq!(s.state_root().unwrap(), root);
    }

    #[test]
    fn cancel_and_height_expiry_release_escrow() {
        let (mut s, p) = setup();
        let buyer = acct(1);
        let seller = acct(2);
        s.credit_genesis(Q, buyer, 100_000).unwrap();
        s.credit_genesis(B, seller, 500).unwrap();
        let bid = submit(&mut s, p, buyer, Side::Buy, 5, 2, Tif::Gtc, 1, 0x41);
        let locked = s.escrow(Q, buyer).unwrap();
        assert!(locked > 0);
        assert_eq!(s.cancel(bid.order_id, buyer).unwrap(), locked);
        assert_eq!(s.escrow(Q, buyer).unwrap(), 0);
        assert_eq!(s.balance(&Q, &buyer), 100_000);
        let ask = submit(&mut s, p, seller, Side::Sell, 7, 3, Tif::Gtc, 2, 0x42);
        assert_eq!(s.escrow(B, seller).unwrap(), 300);
        assert_eq!(s.expire(102).unwrap(), vec![ask.order_id]);
        assert_eq!(s.escrow(B, seller).unwrap(), 0);
        assert_eq!(s.balance(&B, &seller), 500);
    }

    #[test]
    fn self_trade_rejection_is_atomic() {
        let (mut s, p) = setup();
        let owner = acct(1);
        s.credit_genesis(B, owner, 100).unwrap();
        s.credit_genesis(Q, owner, 10_000).unwrap();
        let ask = submit(&mut s, p, owner, Side::Sell, 2, 1, Tif::Gtc, 1, 0x51);
        let root = s.state_root().unwrap();
        let result = s.place(PlaceLimit {
            pair: p,
            owner,
            side: Side::Buy,
            price_ticks: 3,
            quantity_lots: 1,
            tif: Tif::Ioc,
            expires_at_height: 200,
            priority: Priority {
                height: 2,
                tx_index: 0,
                op_index: 0,
            },
            transaction_id: [0x52; 32],
            operation_index: 0,
        });
        assert_eq!(result, Err(Error::SelfTrade));
        assert_eq!(s.state_root().unwrap(), root);
        assert!(s.order(&ask.order_id).is_some());
        let root_a = s.state_root().unwrap();
        let clone = s.clone();
        assert_eq!(root_a, clone.state_root().unwrap());
    }

    #[test]
    fn ioc_with_no_liquidity_refunds_all_locked_quote() {
        let (mut s, p) = setup();
        let buyer = acct(1);
        s.credit_genesis(Q, buyer, 10_000).unwrap();
        let result = submit(&mut s, p, buyer, Side::Buy, 5, 2, Tif::Ioc, 1, 0x61);
        assert_eq!((result.filled_lots, result.remaining_lots), (0, 2));
        assert_eq!(s.balance(&Q, &buyer), 10_000);
        assert_eq!(s.escrow(Q, buyer).unwrap(), 0);
        assert!(s.order(&result.order_id).is_none());
        assert!(s.fills().is_empty());
    }

    #[test]
    fn replaying_identical_operations_produces_identical_fill_ids_and_roots() {
        let (mut a, pair) = setup();
        let mut b = a.clone();
        let buyer = acct(1);
        let seller = acct(2);
        for state in [&mut a, &mut b] {
            state.credit_genesis(B, seller, 200).unwrap();
            state.credit_genesis(Q, buyer, 20_000).unwrap();
        }
        for state in [&mut a, &mut b] {
            submit(state, pair, seller, Side::Sell, 2, 2, Tif::Gtc, 1, 0x62);
            submit(state, pair, buyer, Side::Buy, 3, 2, Tif::Ioc, 2, 0x63);
        }
        assert_eq!(a.fills(), b.fills());
        assert_eq!(a.state_root().unwrap(), b.state_root().unwrap());
        assert_eq!(
            a.total_asset_balance(B).unwrap(),
            b.total_asset_balance(B).unwrap()
        );
        assert_eq!(
            a.total_asset_balance(Q).unwrap(),
            b.total_asset_balance(Q).unwrap()
        );
    }

    #[test]
    fn resting_bid_matches_taker_sell_at_maker_price_and_conserves_both_assets() {
        let (mut s, p) = setup();
        let buyer = acct(1);
        let seller = acct(2);
        s.credit_genesis(Q, buyer, 10_000).unwrap();
        s.credit_genesis(B, seller, 300).unwrap();
        let bid = submit(&mut s, p, buyer, Side::Buy, 2, 3, Tif::Gtc, 1, 0x68);
        let ask = submit(&mut s, p, seller, Side::Sell, 1, 2, Tif::Ioc, 2, 0x69);
        assert_eq!((ask.filled_lots, ask.remaining_lots), (2, 0));
        assert_eq!(s.fills()[0].price_ticks, 2);
        assert_eq!(s.fills()[0].buyer_fee, 1);
        assert_eq!(s.fills()[0].seller_fee, 1);
        assert_eq!(s.balance(&B, &buyer), 200);
        assert_eq!(s.balance(&B, &seller), 100);
        assert_eq!(s.balance(&Q, &seller), 399);
        assert_eq!(s.balance(&Q, &FEES), 2);
        assert_eq!(s.escrow(Q, buyer).unwrap(), 201);
        assert_eq!(s.order(&bid.order_id).unwrap().remaining_lots, 1);
        assert_eq!(s.total_asset_balance(B).unwrap(), 300);
        assert_eq!(s.total_asset_balance(Q).unwrap(), 10_000);
    }

    #[test]
    fn partial_fill_rests_with_sufficient_remaining_escrow() {
        let (mut s, p) = setup();
        let buyer = acct(1);
        let seller = acct(2);
        s.credit_genesis(Q, buyer, 10_000).unwrap();
        s.credit_genesis(B, seller, 100).unwrap();
        submit(&mut s, p, seller, Side::Sell, 2, 1, Tif::Gtc, 1, 0x6a);
        let bid = submit(&mut s, p, buyer, Side::Buy, 3, 3, Tif::Gtc, 2, 0x6b);
        assert_eq!((bid.filled_lots, bid.remaining_lots), (1, 2));
        let resting = s.order(&bid.order_id).unwrap();
        assert_eq!(resting.locked_atoms, 701);
        assert_eq!(s.escrow(Q, buyer).unwrap(), 701);
        assert_eq!(s.balance(&Q, &buyer), 9_098);
        assert_eq!(s.balance(&Q, &seller), 199);
        assert_eq!(s.balance(&Q, &FEES), 2);
        s.verify().unwrap();
        assert_eq!(s.total_asset_balance(Q).unwrap(), 10_000);
    }

    #[test]
    fn due_expiries_must_be_processed_before_any_order_can_match() {
        let (mut s, p) = setup();
        let seller = acct(2);
        let buyer = acct(1);
        s.credit_genesis(B, seller, 100).unwrap();
        s.credit_genesis(Q, buyer, 10_000).unwrap();
        let expired_ask = s
            .place(PlaceLimit {
                pair: p,
                owner: seller,
                side: Side::Sell,
                price_ticks: 2,
                quantity_lots: 1,
                tif: Tif::Gtc,
                expires_at_height: 2,
                priority: Priority {
                    height: 1,
                    tx_index: 0,
                    op_index: 0,
                },
                transaction_id: [0x70; 32],
                operation_index: 0,
            })
            .unwrap();
        let before = s.state_root().unwrap();
        let attempt = s.place(PlaceLimit {
            pair: p,
            owner: buyer,
            side: Side::Buy,
            price_ticks: 2,
            quantity_lots: 1,
            tif: Tif::Ioc,
            expires_at_height: 200,
            priority: Priority {
                height: 2,
                tx_index: 0,
                op_index: 0,
            },
            transaction_id: [0x71; 32],
            operation_index: 0,
        });
        assert_eq!(attempt, Err(Error::ExpiryNotProcessed));
        assert_eq!(s.state_root().unwrap(), before);
        assert_eq!(s.expire(2).unwrap(), vec![expired_ask.order_id]);
        let after_expiry = submit(&mut s, p, buyer, Side::Buy, 2, 1, Tif::Ioc, 2, 0x72);
        assert_eq!(
            (after_expiry.filled_lots, after_expiry.remaining_lots),
            (0, 1)
        );
        assert_eq!(s.balance(&B, &buyer), 0);
        assert_eq!(s.balance(&Q, &buyer), 10_000);
    }

    #[test]
    fn fill_ids_are_unique_for_multiple_operations_in_one_transaction() {
        let (mut s, p) = setup();
        let buyer = acct(1);
        let seller = acct(2);
        s.credit_genesis(B, seller, 300).unwrap();
        s.credit_genesis(Q, buyer, 10_000).unwrap();
        submit(&mut s, p, seller, Side::Sell, 2, 3, Tif::Gtc, 1, 0x81);
        let txid = [0x82; 32];
        let first = s
            .place(PlaceLimit {
                pair: p,
                owner: buyer,
                side: Side::Buy,
                price_ticks: 2,
                quantity_lots: 1,
                tif: Tif::Ioc,
                expires_at_height: 200,
                priority: Priority {
                    height: 2,
                    tx_index: 4,
                    op_index: 0,
                },
                transaction_id: txid,
                operation_index: 0,
            })
            .unwrap();
        let second = s
            .place(PlaceLimit {
                pair: p,
                owner: buyer,
                side: Side::Buy,
                price_ticks: 2,
                quantity_lots: 1,
                tif: Tif::Ioc,
                expires_at_height: 200,
                priority: Priority {
                    height: 2,
                    tx_index: 4,
                    op_index: 1,
                },
                transaction_id: txid,
                operation_index: 1,
            })
            .unwrap();
        assert_eq!(first.filled_lots, 1);
        assert_eq!(second.filled_lots, 1);
        assert_ne!(first.order_id, second.order_id);
        assert_ne!(first.fill_ids[0], second.fill_ids[0]);
        assert_eq!(s.fills().len(), 2);
    }

    #[test]
    fn operation_priority_index_must_match_canonical_operation_id() {
        let (mut s, p) = setup();
        let buyer = acct(1);
        s.credit_genesis(Q, buyer, 10_000).unwrap();
        let before = s.state_root().unwrap();
        let result = s.place(PlaceLimit {
            pair: p,
            owner: buyer,
            side: Side::Buy,
            price_ticks: 2,
            quantity_lots: 1,
            tif: Tif::Gtc,
            expires_at_height: 200,
            priority: Priority {
                height: 1,
                tx_index: 0,
                op_index: 0,
            },
            transaction_id: [0x83; 32],
            operation_index: 1,
        });
        assert_eq!(result, Err(Error::InvalidPriority));
        assert_eq!(s.state_root().unwrap(), before);
    }

    #[test]
    fn order_id_cannot_be_reused_after_it_was_a_filled_maker() {
        let (mut s, p) = setup();
        let buyer = acct(1);
        let seller = acct(2);
        s.credit_genesis(B, seller, 200).unwrap();
        s.credit_genesis(Q, buyer, 20_000).unwrap();
        let ask = submit(&mut s, p, seller, Side::Sell, 2, 2, Tif::Gtc, 1, 0x71);
        submit(&mut s, p, buyer, Side::Buy, 2, 2, Tif::Ioc, 2, 0x72);
        let before = s.state_root().unwrap();
        let duplicate = s.place(PlaceLimit {
            pair: p,
            owner: seller,
            side: Side::Sell,
            price_ticks: 2,
            quantity_lots: 1,
            tif: Tif::Gtc,
            expires_at_height: 200,
            priority: Priority {
                height: 3,
                tx_index: 0,
                op_index: 0,
            },
            transaction_id: [0x71; 32],
            operation_index: 0,
        });
        assert_eq!(duplicate, Err(Error::DuplicateOrder));
        assert_eq!(s.state_root().unwrap(), before);
        assert!(s.order(&ask.order_id).is_none());
    }
}
