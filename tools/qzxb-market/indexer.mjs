import { buildCandles, candleSourceLabel } from './candles.mjs';

const SWAP_TOPIC0 = '0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822';
const TOKEN0_SELECTOR = '0x0dfe1681';
const TOKEN1_SELECTOR = '0xd21220a7';
const DECIMALS_SELECTOR = '0x313ce567';
const GET_PAIR_SELECTOR = '0xe6a43905';

function asHexQuantity(value, name) {
  if (!Number.isSafeInteger(value) || value < 0) throw new RangeError(`${name} must be a non-negative safe integer`);
  return `0x${value.toString(16)}`;
}
function quantityToNumber(value, name) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]+$/.test(value)) throw new TypeError(`${name} must be an RPC hex quantity`);
  const n = Number(BigInt(value));
  if (!Number.isSafeInteger(n)) throw new RangeError(`${name} exceeds JavaScript safe integer range`);
  return n;
}
function addressFromWord(value, name) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(value)) throw new Error(`${name} returned malformed ABI data`);
  return `0x${value.slice(-40).toLowerCase()}`;
}
function uintFromWord(value, name) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(value)) throw new Error(`${name} returned malformed ABI data`);
  return Number(BigInt(value));
}
function dataWord(data, word, name) {
  if (typeof data !== 'string' || !/^0x(?:[0-9a-fA-F]{64}){4}$/.test(data)) throw new Error(`${name} event data must contain four uint256 words`);
  return BigInt(`0x${data.slice(2 + word * 64, 2 + (word + 1) * 64)}`);
}
function normalizedLogSignature(log) {
  if (!log || !Array.isArray(log.topics) || typeof log.data !== 'string') throw new Error('RPC returned malformed swap log');
  return {
    address: lowerAddress(log.address, 'swap log address'),
    topics: log.topics.map((topic) => {
      if (typeof topic !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(topic)) throw new Error('RPC returned malformed log topic');
      return topic.toLowerCase();
    }),
    data: log.data.toLowerCase(),
    blockNumber: quantityToNumber(log.blockNumber, 'log.blockNumber'),
    blockHash: typeof log.blockHash === 'string' ? log.blockHash.toLowerCase() : '',
    transactionHash: typeof log.transactionHash === 'string' ? log.transactionHash.toLowerCase() : '',
    transactionIndex: log.transactionIndex?.toLowerCase?.() ?? '',
    logIndex: quantityToNumber(log.logIndex, 'log.logIndex'),
    removed: log.removed === true,
  };
}

function sortedLogSignatures(logs) {
  return logs.map(normalizedLogSignature).sort((a, b) => a.blockNumber - b.blockNumber || a.logIndex - b.logIndex);
}

function lowerAddress(value, name) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value)) throw new TypeError(`${name} must be a 20-byte hex address`);
  return value.toLowerCase();
}
async function mapBounded(values, concurrency, fn) {
  const out = new Array(values.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, values.length) }, async () => {
    while (true) {
      const i = next++;
      if (i >= values.length) return;
      out[i] = await fn(values[i], i);
    }
  }));
  return out;
}

/**
 * Query a Uniswap-V2-compatible pair directly through JSON-RPC, verify its token identities,
 * inspect confirmed Swap logs, and build OHLC from logs whose block hashes match canonical blocks.
 * The configured quote-token address must be the official deployment on this exact chain; a
 * symbol alone is not identity. This function deliberately refuses unknown or wrong-chain feeds.
 */
export async function loadCandlesFromRpc({
  rpcUrl, verificationRpcUrl, expectedChainId, pairAddress, factoryAddress, baseTokenAddress, quoteTokenAddress,
  fromBlock, toBlock, timeframe, minimumConfirmations = 6, maxBlockSpan = 2_000,
  fetchImpl = globalThis.fetch,
}) {
  if (typeof rpcUrl !== 'string' || !/^https?:\/\//i.test(rpcUrl)) throw new TypeError('rpcUrl must be an HTTP(S) endpoint');
  if (typeof verificationRpcUrl !== 'string' || !/^https?:\/\//i.test(verificationRpcUrl)) throw new TypeError('verificationRpcUrl must be an independent HTTP(S) endpoint');
  if (new URL(rpcUrl).origin === new URL(verificationRpcUrl).origin) throw new Error('primary and verification RPC endpoints must have different origins');
  if (!Number.isSafeInteger(expectedChainId) || expectedChainId <= 0) throw new RangeError('expectedChainId must be a positive safe integer');
  if (!Number.isSafeInteger(fromBlock) || fromBlock < 0) throw new RangeError('fromBlock must be a non-negative safe integer');
  if (toBlock !== undefined && (!Number.isSafeInteger(toBlock) || toBlock < fromBlock)) throw new RangeError('toBlock must be at least fromBlock');
  if (!Number.isInteger(minimumConfirmations) || minimumConfirmations < 1) throw new RangeError('minimumConfirmations must be positive');
  if (!Number.isInteger(maxBlockSpan) || maxBlockSpan < 1 || maxBlockSpan > 50_000) throw new RangeError('maxBlockSpan must be from 1 to 50000');
  if (typeof fetchImpl !== 'function') throw new TypeError('fetchImpl must be a fetch-compatible function');

  pairAddress = lowerAddress(pairAddress, 'pairAddress');
  factoryAddress = lowerAddress(factoryAddress, 'factoryAddress');
  baseTokenAddress = lowerAddress(baseTokenAddress, 'baseTokenAddress');
  quoteTokenAddress = lowerAddress(quoteTokenAddress, 'quoteTokenAddress');
  if (baseTokenAddress === quoteTokenAddress) throw new Error('base and quote token addresses must differ');

  let requestId = 0;
  async function rpc(method, params) {
    const id = ++requestId;
    const response = await fetchImpl(rpcUrl, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
    });
    if (!response || response.ok !== true) throw new Error(`RPC transport failed for ${method}`);
    const payload = await response.json();
    if (payload?.jsonrpc !== '2.0' || payload.id !== id) throw new Error(`RPC response identity mismatch for ${method}`);
    if (payload.error) throw new Error(`RPC ${method} error: ${String(payload.error.message ?? 'unknown error')}`);
    if (!Object.hasOwn(payload, 'result')) throw new Error(`RPC ${method} omitted result`);
    return payload.result;
  }

  let verificationRequestId = 0;
  async function verifyRpc(method, params) {
    const id = ++verificationRequestId;
    const response = await fetchImpl(verificationRpcUrl, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
    });
    if (!response || response.ok !== true) throw new Error(`verification RPC transport failed for ${method}`);
    const payload = await response.json();
    if (payload?.jsonrpc !== '2.0' || payload.id !== id) throw new Error(`verification RPC response identity mismatch for ${method}`);
    if (payload.error) throw new Error(`verification RPC ${method} error: ${String(payload.error.message ?? 'unknown error')}`);
    if (!Object.hasOwn(payload, 'result')) throw new Error(`verification RPC ${method} omitted result`);
    return payload.result;
  }

  const chainId = BigInt(await rpc('eth_chainId', []));
  const verificationChainId = BigInt(await verifyRpc('eth_chainId', []));
  if (verificationChainId !== BigInt(expectedChainId) || verificationChainId !== chainId) throw new Error('verification RPC chain ID mismatch');
  if (chainId !== BigInt(expectedChainId)) throw new Error(`wrong chain id: expected ${expectedChainId}, got ${chainId}`);
  const code = await rpc('eth_getCode', [pairAddress, 'latest']);
  const verificationCode = await verifyRpc('eth_getCode', [pairAddress, 'latest']);
  if (typeof verificationCode !== 'string' || code.toLowerCase() !== verificationCode.toLowerCase()) throw new Error('primary and verification RPC disagree on pair contract bytecode');
  if (typeof code !== 'string' || !/^0x[0-9a-fA-F]*$/.test(code) || code === '0x' || /^0x0*$/.test(code)) {
    throw new Error('configured pair address has no deployed contract code');
  }
  const factoryCode = await rpc('eth_getCode', [factoryAddress, 'latest']);
  const verificationFactoryCode = await verifyRpc('eth_getCode', [factoryAddress, 'latest']);
  if (typeof verificationFactoryCode !== 'string' || factoryCode.toLowerCase() !== verificationFactoryCode.toLowerCase()) throw new Error('primary and verification RPC disagree on factory contract bytecode');
  if (typeof factoryCode !== 'string' || !/^0x[0-9a-fA-F]*$/.test(factoryCode) || factoryCode === '0x' || /^0x0*$/.test(factoryCode)) throw new Error('configured factory address has no deployed contract code');
  const token0 = addressFromWord(await rpc('eth_call', [{ to: pairAddress, data: TOKEN0_SELECTOR }, 'latest']), 'pair.token0()');
  const token1 = addressFromWord(await rpc('eth_call', [{ to: pairAddress, data: TOKEN1_SELECTOR }, 'latest']), 'pair.token1()');
  const verificationToken0 = addressFromWord(await verifyRpc('eth_call', [{ to: pairAddress, data: TOKEN0_SELECTOR }, 'latest']), 'verification pair.token0()');
  const verificationToken1 = addressFromWord(await verifyRpc('eth_call', [{ to: pairAddress, data: TOKEN1_SELECTOR }, 'latest']), 'verification pair.token1()');
  if (verificationToken0 !== token0 || verificationToken1 !== token1) throw new Error('primary and verification RPC disagree on pair token order');
  const exactPair = (token0 === baseTokenAddress && token1 === quoteTokenAddress) || (token0 === quoteTokenAddress && token1 === baseTokenAddress);
  if (token0 === token1 || !exactPair) {
    throw new Error('configured pair token addresses do not exactly match the requested base/quote pair');
  }
  const getPairData = GET_PAIR_SELECTOR + token0.slice(2).padStart(64, '0') + token1.slice(2).padStart(64, '0');
  const factoryPair = addressFromWord(await rpc('eth_call', [{ to: factoryAddress, data: getPairData }, 'latest']), 'factory.getPair()');
  const verificationFactoryPair = addressFromWord(await verifyRpc('eth_call', [{ to: factoryAddress, data: getPairData }, 'latest']), 'verification factory.getPair()');
  if (verificationFactoryPair !== factoryPair) throw new Error('primary and verification RPC disagree on factory getPair mapping');
  if (factoryPair !== pairAddress) throw new Error('factory does not map requested tokens to configured pair');
  const baseDecimals = uintFromWord(await rpc('eth_call', [{ to: baseTokenAddress, data: DECIMALS_SELECTOR }, 'latest']), 'base token decimals');
  const verificationBaseDecimals = uintFromWord(await verifyRpc('eth_call', [{ to: baseTokenAddress, data: DECIMALS_SELECTOR }, 'latest']), 'verification base token decimals');
  const quoteDecimals = uintFromWord(await rpc('eth_call', [{ to: quoteTokenAddress, data: DECIMALS_SELECTOR }, 'latest']), 'quote token decimals');
  const verificationQuoteDecimals = uintFromWord(await verifyRpc('eth_call', [{ to: quoteTokenAddress, data: DECIMALS_SELECTOR }, 'latest']), 'verification quote token decimals');
  if (verificationBaseDecimals !== baseDecimals || verificationQuoteDecimals !== quoteDecimals) throw new Error('primary and verification RPC disagree on token decimals');
  if (baseDecimals > 36 || quoteDecimals > 36) throw new Error('token decimals exceed supported 36-decimal limit');

  const primaryLatestBlock = quantityToNumber(await rpc('eth_blockNumber', []), 'eth_blockNumber');
  const verificationLatestBlock = quantityToNumber(await verifyRpc('eth_blockNumber', []), 'verification eth_blockNumber');
  const latestBlock = Math.min(primaryLatestBlock, verificationLatestBlock);
  const lastSafeBlock = latestBlock - minimumConfirmations + 1;
  const endBlock = toBlock === undefined ? lastSafeBlock : toBlock;
  if (endBlock > lastSafeBlock) throw new Error('requested toBlock has insufficient confirmation depth');
  if (endBlock < fromBlock) {
    return { candles: [], source: candleSourceLabel({ chainName: `chain-${expectedChainId}`, chainId: expectedChainId,
      pairAddress, quoteTokenAddress, minimumConfirmations }), scannedFromBlock: fromBlock, scannedToBlock: endBlock,
      latestBlock, confirmedSwapCount: 0 };
  }

  const logs = [];
  for (let start = fromBlock; start <= endBlock; start += maxBlockSpan) {
    const end = Math.min(endBlock, start + maxBlockSpan - 1);
    const batch = await rpc('eth_getLogs', [{ address: pairAddress,
      fromBlock: asHexQuantity(start, 'fromBlock'), toBlock: asHexQuantity(end, 'toBlock'), topics: [SWAP_TOPIC0] }]);
    const verificationBatch = await verifyRpc('eth_getLogs', [{ address: pairAddress,
      fromBlock: asHexQuantity(start, 'fromBlock'), toBlock: asHexQuantity(end, 'toBlock'), topics: [SWAP_TOPIC0] }]);
    if (!Array.isArray(verificationBatch)) throw new Error('verification eth_getLogs returned a non-array result');
    if (JSON.stringify(sortedLogSignatures(batch)) !== JSON.stringify(sortedLogSignatures(verificationBatch))) throw new Error('primary and verification RPC disagree on Swap logs');
    if (!Array.isArray(batch)) throw new Error('eth_getLogs returned a non-array result');
    logs.push(...batch);
  }

  const blockNumbers = [...new Set(logs.map(log => quantityToNumber(log.blockNumber, 'log.blockNumber')))];
  const canonicalBlocks = new Map(await Promise.all(blockNumbers.map(async number => {
    const block = await rpc('eth_getBlockByNumber', [asHexQuantity(number, 'block number'), false]);
    const verificationBlock = await verifyRpc('eth_getBlockByNumber', [asHexQuantity(number, 'block number'), false]);
    if (!verificationBlock || typeof verificationBlock.hash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(verificationBlock.hash)) throw new Error('verification RPC missing canonical block');
    const verificationTimestamp = quantityToNumber(verificationBlock.timestamp, 'verification block timestamp');
    if (block.hash.toLowerCase() !== verificationBlock.hash.toLowerCase() || quantityToNumber(block.timestamp, 'block timestamp') !== verificationTimestamp) throw new Error('primary and verification RPC disagree on canonical block');
    if (!block || typeof block.hash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(block.hash)) throw new Error(`missing canonical block ${number}`);
    return [number, { hash: block.hash.toLowerCase(), timestamp: quantityToNumber(block.timestamp, `block ${number} timestamp`) }];
  })));

  const events = [];
  for (const log of logs) {
    if (!log || lowerAddress(log.address, 'swap log address') !== pairAddress) throw new Error('swap log address does not match configured pair');
    if (log.removed === true || !Array.isArray(log.topics) || log.topics[0]?.toLowerCase() !== SWAP_TOPIC0) continue;
    const blockNumber = quantityToNumber(log.blockNumber, 'log.blockNumber');
    const canonical = canonicalBlocks.get(blockNumber);
    if (!canonical || typeof log.blockHash !== 'string' || canonical.hash !== log.blockHash.toLowerCase()) continue;
    if (typeof log.transactionHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(log.transactionHash)) throw new Error('swap log has malformed transaction hash');
    const logIndex = quantityToNumber(log.logIndex, 'log.logIndex');
    events.push({
      pairAddress, token0, token1, blockNumber, blockTimestamp: canonical.timestamp,
      blockHash: canonical.hash, transactionHash: log.transactionHash.toLowerCase(), logIndex,
      confirmations: latestBlock - blockNumber + 1, canonical: true,
      amount0In: dataWord(log.data, 0, 'Swap'), amount1In: dataWord(log.data, 1, 'Swap'),
      amount0Out: dataWord(log.data, 2, 'Swap'), amount1Out: dataWord(log.data, 3, 'Swap'),
    });
  }
  const candles = buildCandles(events, { pairAddress, token0, token1, baseTokenAddress,
    baseDecimals, quoteDecimals, timeframe, minimumConfirmations });
  return {
    candles,
    source: candleSourceLabel({ chainName: `chain-${expectedChainId}`, chainId: expectedChainId,
      pairAddress, quoteTokenAddress, minimumConfirmations }),
    scannedFromBlock: fromBlock, scannedToBlock: endBlock, latestBlock, confirmedSwapCount: events.length,
  };
}

export const UNISWAP_V2_SWAP_TOPIC0 = SWAP_TOPIC0;
