import test from 'node:test';
import assert from 'node:assert/strict';
import { buildNativeCandles } from './native-candles.mjs';

const pairId = 'aa'.repeat(32);
const baseId = '11'.repeat(32);
const quoteId = '22'.repeat(32);
const hash = n => n.toString(16).padStart(64, '0');
const timestamp = Date.UTC(2026, 9, 27, 10, 0, 0) / 1000;
const block = {
  height: 10,
  block_hash: hash(10),
  timestamp,
  confirmations: 6,
  canonical: true,
  swaps: [{
    operation_index: 1, pair_id: pairId, token_in: baseId, token_out: quoteId,
    amount_in_atoms: '100000000', amount_out_atoms: '2000000', fee_atoms: '6000',
    reserve0_after_atoms: '100000000', reserve1_after_atoms: '2000000',
  }],
};
const config = {
  pairId, baseTokenId: baseId, quoteTokenId: quoteId,
  baseDecimals: 8, quoteDecimals: 6, timeframe: '1h', minimumConfirmations: 3,
};

test('calculates native QZXB-base quote-per-base OHLC using token decimals', () => {
  const [candle] = buildNativeCandles([block], config);
  assert.equal(candle.open, '2');
  assert.equal(candle.high, '2');
  assert.equal(candle.low, '2');
  assert.equal(candle.close, '2');
  assert.equal(candle.baseVolumeAtoms, '100000000');
  assert.equal(candle.quoteVolumeAtoms, '2000000');
  assert.equal(candle.tradeCount, 1);
  assert.equal(candle.firstOperationIndex, 1);
});

test('sorts by canonical block and operation order, dedupes overlapping pages', () => {
  const later = {
    ...block, height: 11, block_hash: hash(11), timestamp: timestamp + 120,
    swaps: [{
      operation_index: 0, pair_id: pairId, token_in: quoteId, token_out: baseId,
      amount_in_atoms: '1000000', amount_out_atoms: '100000000', fee_atoms: '3000',
      reserve0_after_atoms: '200000000', reserve1_after_atoms: '3000000',
    }],
  };
  const [candle] = buildNativeCandles([later, block, JSON.parse(JSON.stringify(block))], config);
  assert.equal(candle.open, '2');
  assert.equal(candle.close, '1');
  assert.equal(candle.high, '2');
  assert.equal(candle.low, '1');
  assert.equal(candle.baseVolumeAtoms, '200000000');
  assert.equal(candle.quoteVolumeAtoms, '3000000');
  assert.equal(candle.tradeCount, 2);
});

test('excludes noncanonical and insufficiently confirmed blocks', () => {
  assert.deepEqual(buildNativeCandles([
    { ...block, canonical: false },
    { ...block, confirmations: 2 },
  ], config), []);
});

test('supports weekly and monthly UTC buckets', () => {
  const weekly = buildNativeCandles([block], { ...config, timeframe: '1w' });
  const monthly = buildNativeCandles([block], { ...config, timeframe: '1M' });
  assert.equal(new Date(weekly[0].startTime * 1000).toISOString(), '2026-10-26T00:00:00.000Z');
  assert.equal(new Date(monthly[0].startTime * 1000).toISOString(), '2026-10-01T00:00:00.000Z');
  assert.equal(new Date(monthly[0].endTime * 1000).toISOString(), '2026-11-01T00:00:00.000Z');
});

test('rejects conflicting canonical hashes at the same height after a reorg', () => {
  assert.throws(() => buildNativeCandles([
    block, { ...block, block_hash: hash(99) },
  ], config), /conflicting canonical block hashes/);
});

test('rejects asset mismatch, conflicting duplicate operations and invalid IDs', () => {
  const mismatch = { ...block, swaps: [{ ...block.swaps[0], token_out: '33'.repeat(32) }] };
  assert.throws(() => buildNativeCandles([mismatch], config), /do not match/);
  const duplicate = { ...block, swaps: [block.swaps[0], { ...block.swaps[0], amount_out_atoms: '3000000' }] };
  assert.throws(() => buildNativeCandles([duplicate], config), /conflicting contents/);
  assert.throws(() => buildNativeCandles([block], { ...config, pairId: 'bad' }), /32-byte hex ID/);
});
