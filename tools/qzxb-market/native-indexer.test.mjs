import test from 'node:test';
import assert from 'node:assert/strict';
import { fetchNativeCandles } from './native-indexer.mjs';

const pairId = 'aa'.repeat(32);
const baseId = '11'.repeat(32);
const quoteId = '22'.repeat(32);
const hash = n => n.toString(16).padStart(64, '0');
const identity = {
  ok: true, read_only: true, network_id: '01'.repeat(32), genesis_id: '02'.repeat(32),
  profile_id: '03'.repeat(32), height: 12, tip: hash(12), reorg_count: 0,
  retained_base_height: 0, min_confirmations: 3,
  finality_model: 'probabilistic_pow_confirmations', mainnet: false, public_launch_approved: false,
};
function block(height, amountQuote = '2000000') {
  return {
    height, block_hash: hash(height), timestamp: Date.UTC(2026, 9, 27, 10, 0, 0) / 1000,
    confirmations: 12 - height + 1, canonical: true,
    swaps: [{
      operation_index: 0, pair_id: pairId, token_in: baseId, token_out: quoteId,
      amount_in_atoms: '100000000', amount_out_atoms: amountQuote, fee_atoms: '0',
      reserve0_after_atoms: '0', reserve1_after_atoms: '0',
    }],
  };
}
function response(data) {
  return { ok: true, status: 200, json: async () => data };
}
const config = {
  rpcUrl: 'http://127.0.0.1:49339', pairId, baseTokenId: baseId, quoteTokenId: quoteId,
  baseDecimals: 8, quoteDecimals: 6, timeframe: '1h', minimumConfirmations: 3,
  maxPages: 4,
};

test('fetches bounded pages, builds candles and returns source/trust metadata', async () => {
  const seen = [];
  const fetchImpl = async url => {
    seen.push(url);
    const query = new URL(url).searchParams;
    if (!query.has('before_height')) return response({ ...identity, blocks: [block(10), block(9)] });
    if (query.get('before_height') === '9') return response({ ...identity, blocks: [block(8), block(7)] });
    return response({ ...identity, blocks: [block(1)] });
  };
  const result = await fetchNativeCandles({ ...config, fetchImpl });
  assert.equal(seen.length, 3);
  assert.equal(result.source.pagesFetched, 3);
  assert.equal(result.source.historyComplete, true);
  assert.equal(result.source.synthetic, false);
  assert.equal(result.source.mainnet, false);
  assert.equal(result.candles[0].tradeCount, 5);
  assert.equal(result.candles[0].open, '2');
});

test('fails closed if the canonical tip/reorg identity changes between pages', async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    const data = calls === 1
      ? { ...identity, blocks: [block(12), block(11)] }
      : { ...identity, tip: hash(99), reorg_count: 1, blocks: [block(10)] };
    return response(data);
  };
  await assert.rejects(fetchNativeCandles({ ...config, fetchImpl }), /changed during pagination/);
});

test('refuses incomplete pagination, bad status, and unbounded URLs', async () => {
  const partialFetch = async url => {
    const q = new URL(url).searchParams;
    const data = !q.has('before_height')
      ? { ...identity, blocks: [block(12), block(11)] }
      : { ...identity, blocks: [block(10), block(9)] };
    return response(data);
  };
  await assert.rejects(fetchNativeCandles({ ...config, maxPages: 1, fetchImpl: partialFetch }), /exceeds maxPages/);
  await assert.rejects(fetchNativeCandles({ ...config, fetchImpl: async () => ({ ok: false, status: 503 }) }), /request failed/);
  await assert.rejects(fetchNativeCandles({ ...config, rpcUrl: 'file:///etc/passwd', fetchImpl: async () => response(identity) }), /HTTP\(S\) URL/);
});
