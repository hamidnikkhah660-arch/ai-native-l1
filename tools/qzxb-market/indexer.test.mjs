import test from 'node:test';
import assert from 'node:assert/strict';
import { loadCandlesFromRpc, UNISWAP_V2_SWAP_TOPIC0 } from './indexer.mjs';

const pair = '0x1111111111111111111111111111111111111111';
const base = '0x2222222222222222222222222222222222222222';
const quote = '0x3333333333333333333333333333333333333333';
const factory = '0x4444444444444444444444444444444444444444';
const hash = n => '0x' + BigInt(n).toString(16).padStart(64, '0');
const addrWord = address => '0x' + address.slice(2).toLowerCase().padStart(64, '0');
const word = value => BigInt(value).toString(16).padStart(64, '0');
const timestamp = Math.floor(Date.UTC(2026, 9, 27, 10, 5, 0) / 1000);
const log = (blockNumber = 90, blockHash = hash(blockNumber)) => ({
  address: pair, topics: [UNISWAP_V2_SWAP_TOPIC0], data: '0x' + word(0) + word(2_000_000) + word(100_000_000) + word(0),
  blockNumber: '0x' + blockNumber.toString(16), blockHash, transactionHash: hash(9001), logIndex: '0x0', removed: false,
});

function mockFetch({ chainId = '0x7a69', logs = [log()], canonicalHash = hash(90), pairToken0 = base, pairToken1 = quote, factoryPair = pair } = {}) {
  const calls = [];
  const fetchImpl = async (_url, options) => {
    const req = JSON.parse(options.body);
    calls.push(req);
    let result;
    switch (req.method) {
      case 'eth_chainId': result = chainId; break;
      case 'eth_getCode': result = '0x6001600055'; break;
      case 'eth_blockNumber': result = '0x64'; break;
      case 'eth_call': {
        const { to, data } = req.params[0];
        if (data === '0x0dfe1681' && to.toLowerCase() === pair) result = addrWord(pairToken0);
        else if (data === '0xd21220a7' && to.toLowerCase() === pair) result = addrWord(pairToken1);
        else if (data === '0x313ce567' && to.toLowerCase() === base) result = '0x' + word(8);
        else if (data.startsWith('0xe6a43905') && to.toLowerCase() === factory) {
          const expected = '0xe6a43905' + pairToken0.slice(2).toLowerCase().padStart(64, '0') + pairToken1.slice(2).toLowerCase().padStart(64, '0');
          assert.equal(data, expected);
          result = addrWord(factoryPair);
        }
        else if (data === '0x313ce567' && to.toLowerCase() === quote) result = '0x' + word(6);
        else throw new Error(`unexpected eth_call ${to} ${data}`);
        break;
      }
      case 'eth_getLogs': result = logs; break;
      case 'eth_getBlockByNumber': {
        const n = Number(BigInt(req.params[0]));
        result = { number: req.params[0], hash: n === 90 ? canonicalHash : hash(n), timestamp: '0x' + timestamp.toString(16) };
        break;
      }
      default: throw new Error(`unexpected method ${req.method}`);
    }
    return { ok: true, json: async () => ({ jsonrpc: '2.0', id: req.id, result }) };
  };
  return { fetchImpl, calls };
}

const options = { rpcUrl: 'https://rpc.example.invalid', expectedChainId: 31337,
  pairAddress: pair, factoryAddress: factory, baseTokenAddress: base, quoteTokenAddress: quote,
  fromBlock: 80, timeframe: '1h', minimumConfirmations: 6, maxBlockSpan: 20 };

test('loads canonical confirmed Uniswap-V2-compatible Swap logs into true OHLCV', async () => {
  const mock = mockFetch();
  const result = await loadCandlesFromRpc({ ...options, fetchImpl: mock.fetchImpl });
  assert.equal(result.latestBlock, 100);
  assert.equal(result.scannedFromBlock, 80);
  assert.equal(result.scannedToBlock, 95);
  assert.equal(result.confirmedSwapCount, 1);
  assert.equal(result.candles.length, 1);
  assert.equal(result.candles[0].open, '2');
  assert.equal(result.candles[0].quoteVolumeAtoms, '2000000');
  assert.equal(result.source.synthetic, false);
  assert.equal(result.source.dataKind, 'canonical-confirmed-swaps');
  assert.equal(mock.calls.some(c => c.method === 'eth_getLogs' && c.params[0].topics[0] === UNISWAP_V2_SWAP_TOPIC0), true);
});

test('refuses an RPC on the wrong chain before querying a pair', async () => {
  const mock = mockFetch({ chainId: '0x1' });
  await assert.rejects(loadCandlesFromRpc({ ...options, fetchImpl: mock.fetchImpl }), /wrong chain id/);
  assert.deepEqual(mock.calls.map(c => c.method), ['eth_chainId']);
});

test('refuses fake token identities and wrong base/quote order', async () => {
  const mock = mockFetch({ pairToken0: base, pairToken1: pair });
  await assert.rejects(loadCandlesFromRpc({ ...options, fetchImpl: mock.fetchImpl }), /do not exactly match/);
});

test('requires the configured factory to map both exact token addresses to the pair', async () => {
  const mock = mockFetch({ factoryPair: '0x9999999999999999999999999999999999999999' });
  await assert.rejects(loadCandlesFromRpc({ ...options, fetchImpl: mock.fetchImpl }), /factory does not map/);
});

test('rejects a provider log that claims a different pair address', async () => {
  const mock = mockFetch({ logs: [{ ...log(), address: quote }] });
  await assert.rejects(loadCandlesFromRpc({ ...options, fetchImpl: mock.fetchImpl }), /swap log address/);
});

test('drops logs whose block hash is not the canonical block hash', async () => {
  const mock = mockFetch({ logs: [log(90, hash(999))], canonicalHash: hash(90) });
  const result = await loadCandlesFromRpc({ ...options, fetchImpl: mock.fetchImpl });
  assert.equal(result.confirmedSwapCount, 0);
  assert.equal(result.candles.length, 0);
});

test('rejects a requested range without enough confirmations', async () => {
  const mock = mockFetch();
  await assert.rejects(loadCandlesFromRpc({ ...options, toBlock: 98, fetchImpl: mock.fetchImpl }), /insufficient confirmation depth/);
});

test('uses bounded log ranges to avoid unbounded provider requests', async () => {
  const mock = mockFetch({ logs: [] });
  const result = await loadCandlesFromRpc({ ...options, fromBlock: 0, maxBlockSpan: 20, fetchImpl: mock.fetchImpl });
  const ranges = mock.calls.filter(c => c.method === 'eth_getLogs').map(c => [Number(BigInt(c.params[0].fromBlock)), Number(BigInt(c.params[0].toBlock))]);
  assert.deepEqual(ranges, [[0, 19], [20, 39], [40, 59], [60, 79], [80, 95]]);
  assert.equal(result.candles.length, 0);
});
