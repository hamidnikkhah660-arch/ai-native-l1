//! Candidate native constant-product AMM state machine for QZXB.
//!
//! Deterministic arithmetic and atomic state transitions are implemented here, but this module
//! is NOT yet part of TXN4/QZB4 consensus, node transaction decoding, or persistent snapshots.
//! It must not be used to claim public-market or Mainnet readiness. Production activation must
//! bind these transitions to authenticated transactions, canonical block events and state roots.
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub type AmmAssetId = [u8; 32];
pub type AmmAccountId = [u8; 32];
pub type AmmPairId = [u8; 32];

pub const AMM_FEE_BPS: u128 = 30;
pub const AMM_BPS_DENOMINATOR: u128 = 10_000;
pub const AMM_OUTPUT_MULTIPLIER: u128 = AMM_BPS_DENOMINATOR - AMM_FEE_BPS;
const PAIR_ID_DOMAIN: &[u8] = b"QZXB-NATIVE-AMM-PAIR-V1\0";
const STATE_ROOT_DOMAIN: &[u8] = b"QZXB-NATIVE-AMM-STATE-ROOT-CANDIDATE-V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmmError {
    InvalidResourceLimit,
    InvalidAssetId,
    InvalidAccountId,
    DuplicateAsset,
    UnknownAsset,
    PairAlreadyExists,
    PairNotFound,
    ZeroAmount,
    InsufficientBalance,
    ArithmeticOverflow,
    ArithmeticUnderflow,
    TooManyAssets,
    TooManyPairs,
    TooManyHoldings,
    SlippageLimit,
    InsufficientLiquidity,
    InvariantViolation,
}

impl fmt::Display for AmmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for AmmError {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Pool {
    token0: AmmAssetId,
    token1: AmmAssetId,
    reserve0: u128,
    reserve1: u128,
    total_lp_shares: u128,
    lp_balances: BTreeMap<AmmAccountId, u128>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QzxbAmmStateCandidate {
    registered_assets: BTreeSet<AmmAssetId>,
    balances: BTreeMap<(AmmAssetId, AmmAccountId), u128>,
    pools: BTreeMap<AmmPairId, Pool>,
    max_assets: usize,
    max_pairs: usize,
    max_holdings: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiquidityAdded {
    pub pair_id: AmmPairId,
    pub amount0_used: u128,
    pub amount1_used: u128,
    pub lp_shares_minted: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiquidityRemoved {
    pub pair_id: AmmPairId,
    pub amount0_out: u128,
    pub amount1_out: u128,
    pub lp_shares_burned: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapReceipt {
    pub pair_id: AmmPairId,
    pub token_in: AmmAssetId,
    pub token_out: AmmAssetId,
    pub amount_in: u128,
    pub amount_out: u128,
    pub fee_atoms: u128,
    pub reserve0_after: u128,
    pub reserve1_after: u128,
}

impl QzxbAmmStateCandidate {
    pub fn new(max_assets: usize, max_pairs: usize, max_holdings: usize) -> Result<Self, AmmError> {
        if max_assets == 0 || max_pairs == 0 || max_holdings == 0 {
            return Err(AmmError::InvalidResourceLimit);
        }
        Ok(Self {
            registered_assets: BTreeSet::new(),
            balances: BTreeMap::new(),
            pools: BTreeMap::new(),
            max_assets,
            max_pairs,
            max_holdings,
        })
    }

    pub fn register_asset(&mut self, asset: AmmAssetId) -> Result<(), AmmError> {
        if is_zero(&asset) {
            return Err(AmmError::InvalidAssetId);
        }
        if self.registered_assets.contains(&asset) {
            return Err(AmmError::DuplicateAsset);
        }
        if self.registered_assets.len() >= self.max_assets {
            return Err(AmmError::TooManyAssets);
        }
        self.registered_assets.insert(asset);
        Ok(())
    }

    /// Genesis/bootstrap helper for tests and candidate construction only.
    /// It is not a mint operation suitable for the live transaction path.
    pub fn credit_genesis_balance(
        &mut self,
        asset: AmmAssetId,
        account: AmmAccountId,
        amount: u128,
    ) -> Result<(), AmmError> {
        self.ensure_asset(&asset)?;
        self.ensure_user_account(&account)?;
        if amount == 0 {
            return Err(AmmError::ZeroAmount);
        }
        let next_balance = self
            .balance_of(&asset, &account)
            .checked_add(amount)
            .ok_or(AmmError::ArithmeticOverflow)?;
        if !self.balances.contains_key(&(asset, account))
            && self.balances.len() >= self.max_holdings
        {
            return Err(AmmError::TooManyHoldings);
        }
        self.balances.insert((asset, account), next_balance);
        self.verify_invariants()
    }

    pub fn balance_of(&self, asset: &AmmAssetId, account: &AmmAccountId) -> u128 {
        self.balances.get(&(*asset, *account)).copied().unwrap_or(0)
    }

    pub fn asset_count(&self) -> usize {
        self.registered_assets.len()
    }

    pub fn pair_count(&self) -> usize {
        self.pools.len()
    }

    pub fn pair_id_for_assets(a: AmmAssetId, b: AmmAssetId) -> Result<AmmPairId, AmmError> {
        if is_zero(&a) || is_zero(&b) {
            return Err(AmmError::InvalidAssetId);
        }
        if a == b {
            return Err(AmmError::InvalidAssetId);
        }
        let (token0, token1) = ordered_assets(a, b);
        let mut hash = Sha256::new();
        hash.update(PAIR_ID_DOMAIN);
        hash.update(token0);
        hash.update(token1);
        Ok(hash.finalize().into())
    }

    /// Create an empty permissionless pair for two already registered asset IDs.
    pub fn create_pair(&mut self, a: AmmAssetId, b: AmmAssetId) -> Result<AmmPairId, AmmError> {
        self.ensure_asset(&a)?;
        self.ensure_asset(&b)?;
        let (token0, token1) = ordered_assets(a, b);
        let pair_id = Self::pair_id_for_assets(token0, token1)?;
        if self.pools.contains_key(&pair_id) {
            return Err(AmmError::PairAlreadyExists);
        }
        if self.pools.len() >= self.max_pairs {
            return Err(AmmError::TooManyPairs);
        }
        // The pair ID doubles as the deterministic internal custody account. Refuse a
        // collision with any pre-existing user account or LP holder.
        if self.balances.keys().any(|(_, account)| *account == pair_id)
            || self
                .pools
                .values()
                .any(|pool| pool.lp_balances.contains_key(&pair_id))
        {
            return Err(AmmError::InvariantViolation);
        }
        self.pools.insert(
            pair_id,
            Pool {
                token0,
                token1,
                reserve0: 0,
                reserve1: 0,
                total_lp_shares: 0,
                lp_balances: BTreeMap::new(),
            },
        );
        self.verify_invariants()?;
        Ok(pair_id)
    }

    pub fn reserves(
        &self,
        pair_id: &AmmPairId,
    ) -> Result<(AmmAssetId, u128, AmmAssetId, u128), AmmError> {
        let pool = self.pools.get(pair_id).ok_or(AmmError::PairNotFound)?;
        Ok((pool.token0, pool.reserve0, pool.token1, pool.reserve1))
    }

    pub fn lp_balance_of(
        &self,
        pair_id: &AmmPairId,
        account: &AmmAccountId,
    ) -> Result<u128, AmmError> {
        let pool = self.pools.get(pair_id).ok_or(AmmError::PairNotFound)?;
        Ok(pool.lp_balances.get(account).copied().unwrap_or(0))
    }

    /// Add liquidity; `amount_a` and `amount_b` are desired amounts for canonical token0 and token1.
    pub fn add_liquidity(
        &mut self,
        provider: AmmAccountId,
        pair_id: AmmPairId,
        amount_a: u128,
        amount_b: u128,
        min_lp_shares: u128,
    ) -> Result<LiquidityAdded, AmmError> {
        let mut next = self.clone();
        let receipt =
            next.add_liquidity_inner(provider, pair_id, amount_a, amount_b, min_lp_shares)?;
        next.verify_invariants()?;
        *self = next;
        Ok(receipt)
    }

    fn add_liquidity_inner(
        &mut self,
        provider: AmmAccountId,
        pair_id: AmmPairId,
        amount_a: u128,
        amount_b: u128,
        min_lp_shares: u128,
    ) -> Result<LiquidityAdded, AmmError> {
        self.ensure_user_account(&provider)?;
        if amount_a == 0 || amount_b == 0 || min_lp_shares == 0 {
            return Err(AmmError::ZeroAmount);
        }
        let pool = self
            .pools
            .get(&pair_id)
            .ok_or(AmmError::PairNotFound)?
            .clone();
        // Amounts are ordered by the canonical token0/token1 IDs returned by reserves().
        let (amount0_in, amount1_in) = (amount_a, amount_b);
        if self.balance_of(&pool.token0, &provider) < amount0_in
            || self.balance_of(&pool.token1, &provider) < amount1_in
        {
            return Err(AmmError::InsufficientBalance);
        }

        let (amount0_used, amount1_used, shares) = if pool.total_lp_shares == 0 {
            if pool.reserve0 != 0 || pool.reserve1 != 0 {
                return Err(AmmError::InvariantViolation);
            }
            let product = amount0_in
                .checked_mul(amount1_in)
                .ok_or(AmmError::ArithmeticOverflow)?;
            (amount0_in, amount1_in, integer_sqrt(product))
        } else {
            if pool.reserve0 == 0 || pool.reserve1 == 0 {
                return Err(AmmError::InvariantViolation);
            }
            let amount1_optimal = amount0_in
                .checked_mul(pool.reserve1)
                .ok_or(AmmError::ArithmeticOverflow)?
                / pool.reserve0;
            let (used0, used1) = if amount1_optimal <= amount1_in {
                (amount0_in, amount1_optimal)
            } else {
                (
                    amount1_in
                        .checked_mul(pool.reserve0)
                        .ok_or(AmmError::ArithmeticOverflow)?
                        / pool.reserve1,
                    amount1_in,
                )
            };
            let shares0 = used0
                .checked_mul(pool.total_lp_shares)
                .ok_or(AmmError::ArithmeticOverflow)?
                / pool.reserve0;
            let shares1 = used1
                .checked_mul(pool.total_lp_shares)
                .ok_or(AmmError::ArithmeticOverflow)?
                / pool.reserve1;
            (used0, used1, shares0.min(shares1))
        };
        if amount0_used == 0 || amount1_used == 0 || shares == 0 || shares < min_lp_shares {
            return Err(AmmError::SlippageLimit);
        }

        self.move_balance(pool.token0, provider, pair_id, amount0_used)?;
        self.move_balance(pool.token1, provider, pair_id, amount1_used)?;
        let pool = self.pools.get_mut(&pair_id).ok_or(AmmError::PairNotFound)?;
        pool.reserve0 = pool
            .reserve0
            .checked_add(amount0_used)
            .ok_or(AmmError::ArithmeticOverflow)?;
        pool.reserve1 = pool
            .reserve1
            .checked_add(amount1_used)
            .ok_or(AmmError::ArithmeticOverflow)?;
        pool.total_lp_shares = pool
            .total_lp_shares
            .checked_add(shares)
            .ok_or(AmmError::ArithmeticOverflow)?;
        let lp = pool
            .lp_balances
            .get(&provider)
            .copied()
            .unwrap_or(0)
            .checked_add(shares)
            .ok_or(AmmError::ArithmeticOverflow)?;
        if !pool.lp_balances.contains_key(&provider) && pool.lp_balances.len() >= self.max_holdings
        {
            return Err(AmmError::TooManyHoldings);
        }
        pool.lp_balances.insert(provider, lp);
        Ok(LiquidityAdded {
            pair_id,
            amount0_used,
            amount1_used,
            lp_shares_minted: shares,
        })
    }

    pub fn remove_liquidity(
        &mut self,
        provider: AmmAccountId,
        pair_id: AmmPairId,
        shares: u128,
        min_amount0_out: u128,
        min_amount1_out: u128,
    ) -> Result<LiquidityRemoved, AmmError> {
        let mut next = self.clone();
        let receipt = next.remove_liquidity_inner(
            provider,
            pair_id,
            shares,
            min_amount0_out,
            min_amount1_out,
        )?;
        next.verify_invariants()?;
        *self = next;
        Ok(receipt)
    }

    fn remove_liquidity_inner(
        &mut self,
        provider: AmmAccountId,
        pair_id: AmmPairId,
        shares: u128,
        min_amount0_out: u128,
        min_amount1_out: u128,
    ) -> Result<LiquidityRemoved, AmmError> {
        self.ensure_user_account(&provider)?;
        if shares == 0 || min_amount0_out == 0 || min_amount1_out == 0 {
            return Err(AmmError::ZeroAmount);
        }
        let pool = self
            .pools
            .get(&pair_id)
            .ok_or(AmmError::PairNotFound)?
            .clone();
        let owned = pool.lp_balances.get(&provider).copied().unwrap_or(0);
        if shares > owned || pool.total_lp_shares == 0 {
            return Err(AmmError::InsufficientBalance);
        }
        let amount0_out = pool
            .reserve0
            .checked_mul(shares)
            .ok_or(AmmError::ArithmeticOverflow)?
            / pool.total_lp_shares;
        let amount1_out = pool
            .reserve1
            .checked_mul(shares)
            .ok_or(AmmError::ArithmeticOverflow)?
            / pool.total_lp_shares;
        if amount0_out == 0
            || amount1_out == 0
            || amount0_out < min_amount0_out
            || amount1_out < min_amount1_out
        {
            return Err(AmmError::SlippageLimit);
        }
        self.move_balance(pool.token0, pair_id, provider, amount0_out)?;
        self.move_balance(pool.token1, pair_id, provider, amount1_out)?;
        let pool = self.pools.get_mut(&pair_id).ok_or(AmmError::PairNotFound)?;
        pool.reserve0 -= amount0_out;
        pool.reserve1 -= amount1_out;
        pool.total_lp_shares -= shares;
        let remaining = owned - shares;
        if remaining == 0 {
            pool.lp_balances.remove(&provider);
        } else {
            pool.lp_balances.insert(provider, remaining);
        }
        Ok(LiquidityRemoved {
            pair_id,
            amount0_out,
            amount1_out,
            lp_shares_burned: shares,
        })
    }

    pub fn swap_exact_in(
        &mut self,
        trader: AmmAccountId,
        token_in: AmmAssetId,
        token_out: AmmAssetId,
        amount_in: u128,
        min_amount_out: u128,
    ) -> Result<SwapReceipt, AmmError> {
        let mut next = self.clone();
        let receipt =
            next.swap_exact_in_inner(trader, token_in, token_out, amount_in, min_amount_out)?;
        next.verify_invariants()?;
        *self = next;
        Ok(receipt)
    }

    fn swap_exact_in_inner(
        &mut self,
        trader: AmmAccountId,
        token_in: AmmAssetId,
        token_out: AmmAssetId,
        amount_in: u128,
        min_amount_out: u128,
    ) -> Result<SwapReceipt, AmmError> {
        self.ensure_user_account(&trader)?;
        self.ensure_asset(&token_in)?;
        self.ensure_asset(&token_out)?;
        if amount_in == 0 || min_amount_out == 0 {
            return Err(AmmError::ZeroAmount);
        }
        let pair_id = Self::pair_id_for_assets(token_in, token_out)?;
        if self.balance_of(&token_in, &trader) < amount_in {
            return Err(AmmError::InsufficientBalance);
        }
        let pool = self
            .pools
            .get(&pair_id)
            .ok_or(AmmError::PairNotFound)?
            .clone();
        let (reserve_in, reserve_out, input_is_token0) = if token_in == pool.token0 {
            (pool.reserve0, pool.reserve1, true)
        } else if token_in == pool.token1 {
            (pool.reserve1, pool.reserve0, false)
        } else {
            return Err(AmmError::PairNotFound);
        };
        if reserve_in == 0 || reserve_out == 0 || pool.total_lp_shares == 0 {
            return Err(AmmError::InsufficientLiquidity);
        }
        let amount_in_with_fee = amount_in
            .checked_mul(AMM_OUTPUT_MULTIPLIER)
            .ok_or(AmmError::ArithmeticOverflow)?;
        let numerator = amount_in_with_fee
            .checked_mul(reserve_out)
            .ok_or(AmmError::ArithmeticOverflow)?;
        let denominator = reserve_in
            .checked_mul(AMM_BPS_DENOMINATOR)
            .and_then(|value| value.checked_add(amount_in_with_fee))
            .ok_or(AmmError::ArithmeticOverflow)?;
        let amount_out = numerator / denominator;
        if amount_out == 0 || amount_out < min_amount_out || amount_out >= reserve_out {
            return Err(AmmError::SlippageLimit);
        }
        let old_k = reserve_in
            .checked_mul(reserve_out)
            .ok_or(AmmError::ArithmeticOverflow)?;
        let new_reserve_in = reserve_in
            .checked_add(amount_in)
            .ok_or(AmmError::ArithmeticOverflow)?;
        let new_reserve_out = reserve_out - amount_out;
        let new_k = new_reserve_in
            .checked_mul(new_reserve_out)
            .ok_or(AmmError::ArithmeticOverflow)?;
        if new_k < old_k {
            return Err(AmmError::InvariantViolation);
        }

        self.move_balance(token_in, trader, pair_id, amount_in)?;
        self.move_balance(token_out, pair_id, trader, amount_out)?;
        let pool = self.pools.get_mut(&pair_id).ok_or(AmmError::PairNotFound)?;
        if input_is_token0 {
            pool.reserve0 = new_reserve_in;
            pool.reserve1 = new_reserve_out;
        } else {
            pool.reserve1 = new_reserve_in;
            pool.reserve0 = new_reserve_out;
        }
        let fee_atoms = amount_in - amount_in_with_fee / AMM_BPS_DENOMINATOR;
        Ok(SwapReceipt {
            pair_id,
            token_in,
            token_out,
            amount_in,
            amount_out,
            fee_atoms,
            reserve0_after: pool.reserve0,
            reserve1_after: pool.reserve1,
        })
    }

    pub fn verify_invariants(&self) -> Result<(), AmmError> {
        if self.registered_assets.len() > self.max_assets
            || self.pools.len() > self.max_pairs
            || self.balances.len() > self.max_holdings
        {
            return Err(AmmError::InvariantViolation);
        }
        if self.registered_assets.iter().any(is_zero) {
            return Err(AmmError::InvariantViolation);
        }
        for ((asset, account), amount) in &self.balances {
            if !self.registered_assets.contains(asset) || is_zero(account) || *amount == 0 {
                return Err(AmmError::InvariantViolation);
            }
        }
        for (pair_id, pool) in &self.pools {
            if is_zero(pair_id)
                || pool.token0 >= pool.token1
                || !self.registered_assets.contains(&pool.token0)
                || !self.registered_assets.contains(&pool.token1)
                || Self::pair_id_for_assets(pool.token0, pool.token1)? != *pair_id
                || self.balance_of(&pool.token0, pair_id) != pool.reserve0
                || self.balance_of(&pool.token1, pair_id) != pool.reserve1
            {
                return Err(AmmError::InvariantViolation);
            }
            let sum_lp = pool
                .lp_balances
                .iter()
                .try_fold(0u128, |sum, (account, shares)| {
                    if is_zero(account) || *shares == 0 || self.is_pool_account(account) {
                        return Err(AmmError::InvariantViolation);
                    }
                    sum.checked_add(*shares).ok_or(AmmError::ArithmeticOverflow)
                })?;
            if sum_lp != pool.total_lp_shares {
                return Err(AmmError::InvariantViolation);
            }
            if pool.total_lp_shares == 0 {
                if pool.reserve0 != 0 || pool.reserve1 != 0 || !pool.lp_balances.is_empty() {
                    return Err(AmmError::InvariantViolation);
                }
            } else {
                if pool.reserve0 == 0 || pool.reserve1 == 0 {
                    return Err(AmmError::InvariantViolation);
                }
                pool.reserve0
                    .checked_mul(pool.reserve1)
                    .ok_or(AmmError::ArithmeticOverflow)?;
            }
        }
        Ok(())
    }

    /// Stable candidate root over registered asset IDs, spendable balances, pool reserves and LP shares.
    pub fn state_root(&self) -> Result<[u8; 32], AmmError> {
        self.verify_invariants()?;
        let mut hash = Sha256::new();
        hash.update(STATE_ROOT_DOMAIN);
        // Bind fee policy to the candidate state commitment so implementations using a different
        // fee schedule cannot silently report the same empty-state root.
        hash.update(AMM_FEE_BPS.to_be_bytes());
        hash.update(AMM_BPS_DENOMINATOR.to_be_bytes());
        hash.update((self.registered_assets.len() as u64).to_be_bytes());
        for asset in &self.registered_assets {
            hash.update(asset);
        }
        hash.update((self.balances.len() as u64).to_be_bytes());
        for ((asset, account), amount) in &self.balances {
            hash.update(asset);
            hash.update(account);
            hash.update(amount.to_be_bytes());
        }
        hash.update((self.pools.len() as u64).to_be_bytes());
        for (pair_id, pool) in &self.pools {
            hash.update(pair_id);
            hash.update(pool.token0);
            hash.update(pool.token1);
            hash.update(pool.reserve0.to_be_bytes());
            hash.update(pool.reserve1.to_be_bytes());
            hash.update(pool.total_lp_shares.to_be_bytes());
            hash.update((pool.lp_balances.len() as u64).to_be_bytes());
            for (account, shares) in &pool.lp_balances {
                hash.update(account);
                hash.update(shares.to_be_bytes());
            }
        }
        Ok(hash.finalize().into())
    }

    fn ensure_asset(&self, asset: &AmmAssetId) -> Result<(), AmmError> {
        if is_zero(asset) {
            return Err(AmmError::InvalidAssetId);
        }
        if !self.registered_assets.contains(asset) {
            return Err(AmmError::UnknownAsset);
        }
        Ok(())
    }

    fn ensure_user_account(&self, account: &AmmAccountId) -> Result<(), AmmError> {
        if is_zero(account) || self.is_pool_account(account) {
            return Err(AmmError::InvalidAccountId);
        }
        Ok(())
    }

    fn is_pool_account(&self, account: &AmmAccountId) -> bool {
        self.pools.contains_key(account)
    }

    fn move_balance(
        &mut self,
        asset: AmmAssetId,
        from: AmmAccountId,
        to: AmmAccountId,
        amount: u128,
    ) -> Result<(), AmmError> {
        if amount == 0 {
            return Err(AmmError::ZeroAmount);
        }
        if from == to {
            return Err(AmmError::InvalidAccountId);
        }
        let source = self.balance_of(&asset, &from);
        if source < amount {
            return Err(AmmError::InsufficientBalance);
        }
        let destination = self.balance_of(&asset, &to);
        let next_destination = destination
            .checked_add(amount)
            .ok_or(AmmError::ArithmeticOverflow)?;
        if destination == 0 && self.balances.len() >= self.max_holdings && source != amount {
            return Err(AmmError::TooManyHoldings);
        }
        if source == amount {
            self.balances.remove(&(asset, from));
        } else {
            self.balances.insert((asset, from), source - amount);
        }
        self.balances.insert((asset, to), next_destination);
        Ok(())
    }
}

fn ordered_assets(a: AmmAssetId, b: AmmAssetId) -> (AmmAssetId, AmmAssetId) {
    if a < b {
        (a, b)
    } else {
        (b, a)
    }
}

fn is_zero(value: &[u8; 32]) -> bool {
    value.iter().all(|byte| *byte == 0)
}

fn integer_sqrt(n: u128) -> u128 {
    if n < 2 {
        return n;
    }
    let mut x = n / 2 + 1;
    let mut next = (x + n / x) / 2;
    while next < x {
        x = next;
        next = (x + n / x) / 2;
    }
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: AmmAssetId = [1; 32];
    const B: AmmAssetId = [2; 32];
    const TRADER: AmmAccountId = [3; 32];

    fn fixture() -> (QzxbAmmStateCandidate, AmmPairId) {
        let mut state = QzxbAmmStateCandidate::new(8, 16, 128).unwrap();
        state.register_asset(A).unwrap();
        state.register_asset(B).unwrap();
        state.credit_genesis_balance(A, TRADER, 1_000_000).unwrap();
        state.credit_genesis_balance(B, TRADER, 1_000_000).unwrap();
        let pair = state.create_pair(B, A).unwrap();
        (state, pair)
    }

    #[test]
    fn creates_pair_with_order_independent_id_and_rejects_duplicate() {
        let (mut state, pair) = fixture();
        assert_eq!(
            pair,
            QzxbAmmStateCandidate::pair_id_for_assets(A, B).unwrap()
        );
        assert_eq!(state.create_pair(A, B), Err(AmmError::PairAlreadyExists));
        assert_eq!(state.pair_count(), 1);
    }

    #[test]
    fn adds_liquidity_swaps_with_fee_and_preserves_constant_product() {
        let (mut state, pair) = fixture();
        let added = state
            .add_liquidity(TRADER, pair, 100_000, 100_000, 99_000)
            .unwrap();
        assert_eq!(added.lp_shares_minted, 100_000);
        let (_, reserve0, _, reserve1) = state.reserves(&pair).unwrap();
        let old_k = reserve0 * reserve1;
        let receipt = state.swap_exact_in(TRADER, A, B, 1_000, 1).unwrap();
        assert!(receipt.fee_atoms > 0);
        assert!(receipt.amount_out > 0);
        assert!(receipt.amount_out < 1_000);
        assert!(receipt.reserve0_after * receipt.reserve1_after >= old_k);
        assert_eq!(state.balance_of(&A, &TRADER), 899_000);
        assert_eq!(state.balance_of(&B, &TRADER), 900_000 + receipt.amount_out);
        state.verify_invariants().unwrap();
    }

    #[test]
    fn subsequent_liquidity_uses_optimal_ratio_and_only_debits_used_amounts() {
        let (mut state, pair) = fixture();
        state
            .add_liquidity(TRADER, pair, 100_000, 100_000, 100_000)
            .unwrap();
        let added = state
            .add_liquidity(TRADER, pair, 10_000, 5_000, 5_000)
            .unwrap();
        assert_eq!(added.amount0_used, 5_000);
        assert_eq!(added.amount1_used, 5_000);
        assert_eq!(added.lp_shares_minted, 5_000);
        assert_eq!(state.balance_of(&A, &TRADER), 895_000);
        assert_eq!(state.balance_of(&B, &TRADER), 895_000);
        state.verify_invariants().unwrap();
    }

    #[test]
    fn failed_slippage_is_atomic() {
        let (mut state, pair) = fixture();
        state
            .add_liquidity(TRADER, pair, 100_000, 100_000, 99_000)
            .unwrap();
        let before = state.state_root().unwrap();
        let balances = (state.balance_of(&A, &TRADER), state.balance_of(&B, &TRADER));
        assert_eq!(
            state.swap_exact_in(TRADER, A, B, 1_000, 100_000),
            Err(AmmError::SlippageLimit)
        );
        assert_eq!(state.state_root().unwrap(), before);
        assert_eq!(
            (state.balance_of(&A, &TRADER), state.balance_of(&B, &TRADER)),
            balances
        );
    }

    #[test]
    fn removes_liquidity_and_returns_assets_in_proportion() {
        let (mut state, pair) = fixture();
        let added = state
            .add_liquidity(TRADER, pair, 100_000, 100_000, 100_000)
            .unwrap();
        let removed = state
            .remove_liquidity(TRADER, pair, added.lp_shares_minted / 2, 1, 1)
            .unwrap();
        assert_eq!(removed.amount0_out, 50_000);
        assert_eq!(removed.amount1_out, 50_000);
        assert_eq!(state.lp_balance_of(&pair, &TRADER).unwrap(), 50_000);
        state.verify_invariants().unwrap();
    }

    #[test]
    fn rejects_unknown_assets_and_zero_or_same_asset_pair() {
        let mut state = QzxbAmmStateCandidate::new(2, 2, 2).unwrap();
        state.register_asset(A).unwrap();
        assert_eq!(state.create_pair(A, B), Err(AmmError::UnknownAsset));
        assert_eq!(
            QzxbAmmStateCandidate::pair_id_for_assets(A, A),
            Err(AmmError::InvalidAssetId)
        );
        assert_eq!(
            QzxbAmmStateCandidate::pair_id_for_assets([0; 32], B),
            Err(AmmError::InvalidAssetId)
        );
    }

    #[test]
    fn arithmetic_overflow_does_not_mutate_state() {
        let (mut state, pair) = fixture();
        state
            .add_liquidity(TRADER, pair, 100_000, 100_000, 99_000)
            .unwrap();
        // Build a balance large enough to reach the checked multiplication path.
        let current = state.balance_of(&A, &TRADER);
        state
            .credit_genesis_balance(A, TRADER, u128::MAX - current)
            .unwrap();
        let before = state.state_root().unwrap();
        assert_eq!(
            state.swap_exact_in(TRADER, A, B, u128::MAX, 1),
            Err(AmmError::ArithmeticOverflow)
        );
        assert_eq!(state.state_root().unwrap(), before);
    }
}
