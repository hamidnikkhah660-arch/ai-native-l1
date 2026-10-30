import test from 'node:test';
import assert from 'node:assert/strict';
import { buildCandles, candleSourceLabel } from './candles.mjs';

const pair = '0x1111111111111111111111111111111111111111';
const token0 = '0x2222222222222222222222222222222222222222'; // QZXB/base, 8 decimals
const token1 = '0x3333333333333333333333333333333333333333'; // quote, 6 decimals
const h = n => '0x' + n.toString(16).padStart(64, '0');
const base = { pairAddress: pair, token0, token1, canonical: true, confirmations: 6,
  blockNumber: 10, blockTimestamp: Date.UTC(2026, 9, 27, 10, 0, 0) / 1000,
  blockHash: h(10), transactionHash: h(101), logIndex: 0,
  amount0In: '0', amount1In: '2000000', amount0Out: '100000000', amount1Out: '0' };
const config = { pairAddress: pair, token0, token1, baseTokenAddress: token0,
  baseDecimals: 8, quoteDecimals: 6, timeframe: '1h', minimumConfirmations: 3 };

test('computes quote-per-base prices with differing token decimals', () => {
  const [c] = buildCandles([base], config);
  assert.equal(c.open, '2');
  assert.equal(c.high, '2');
  assert.equal(c.low, '2');
  assert.equal(c.close, '2');
  assert.equal(c.baseVolumeAtoms, '100000000');
  assert.equal(c.quoteVolumeAtoms, '2000000');
  assert.equal(c.tradeCount, 1);
});

test('orders swaps canonically by block and log index, deduplicates provider overlap', () => {
  const later = { ...base, blockNumber: 11, blockTimestamp: base.blockTimestamp + 120,
    blockHash: h(11), transactionHash: h(102), logIndex: 1,
    amount0In: '100000000', amount1In: '0', amount0Out: '0', amount1Out: '1000000' };
  const [c] = buildCandles([later, base, { ...base }], config);
  assert.equal(c.open, '2');
  assert.equal(c.close, '1');
  assert.equal(c.high, '2');
  assert.equal(c.low, '1');
  assert.equal(c.baseVolumeAtoms, '200000000');
  assert.equal(c.quoteVolumeAtoms, '3000000');
  assert.equal(c.tradeCount, 2);
});

test('excludes unconfirmed and noncanonical swaps and emits no empty candles', () => {
  const [c] = buildCandles([
    { ...base, confirmations: 1, blockNumber: 9 },
    { ...base, canonical: false, blockNumber: 8 },
    base,
  ], config);
  assert.equal(c.tradeCount, 1);
  assert.equal(buildCandles([], config).length, 0);
});

test('supports weekly and monthly UTC buckets', () => {
  const tuesday = Date.UTC(2026, 9, 27, 10, 0, 0) / 1000;
  const weekly = buildCandles([{ ...base, blockTimestamp: tuesday }], { ...config, timeframe: '1w' });
  const monthly = buildCandles([{ ...base, blockTimestamp: tuesday }], { ...config, timeframe: '1M' });
  assert.equal(new Date(weekly[0].startTime * 1000).toISOString(), '2026-10-26T00:00:00.000Z');
  assert.equal(new Date(monthly[0].startTime * 1000).toISOString(), '2026-10-01T00:00:00.000Z');
  assert.equal(new Date(monthly[0].endTime * 1000).toISOString(), '2026-11-01T00:00:00.000Z');
});

test('supports reversed base/quote token order', () => {
  const swapped = { ...base, amount0In: '100000000', amount1In: '0', amount0Out: '0', amount1Out: '2000000' };
  const [c] = buildCandles([swapped], { ...config, baseTokenAddress: token1, baseDecimals: 6, quoteDecimals: 8 });
  assert.equal(c.open, '0.5');
});

test('rejects mixed pair identities and malformed hashes', () => {
  assert.throws(() => buildCandles([base], { ...config, token0: token1 }), /pair token identities/);
  assert.throws(() => buildCandles([{ ...base, blockHash: '0x12' }], config), /blockHash/);
});

test('duplicate canonical identity with conflicting contents is rejected', () => {
  const conflict = { ...base, amount1In: '3000000' };
  assert.throws(() => buildCandles([base, conflict], config), /conflicting swap data/);
});

test('source metadata explicitly marks true chain-derived, nonsynthetic series', () => {
  assert.deepEqual(candleSourceLabel({ chainName: 'QuantumZXB', chainId: 123, pairAddress: pair,
    quoteTokenAddress: token1, minimumConfirmations: 12 }), {
    chainName: 'QuantumZXB', chainId: 123, pairAddress: pair, quoteTokenAddress: token1,
    minimumConfirmations: 12, dataKind: 'canonical-confirmed-swaps', synthetic: false,
  });
  assert.throws(() => candleSourceLabel({ chainName: 'QuantumZXB', chainId: 123,
    pairAddress: pair, quoteTokenAddress: token1, minimumConfirmations: 0 }), /source metadata/);
});
