const Q18 = 10n ** 18n;
const DAY = 86_400;
const HOUR = 3_600;

function asBigInt(value, name) {
  try {
    const out = typeof value === 'bigint' ? value : BigInt(value);
    if (out < 0n) throw new Error('negative');
    return out;
  } catch {
    throw new TypeError(`${name} must be a non-negative integer`);
  }
}

function normalizeAddress(value, name) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value)) {
    throw new TypeError(`${name} must be a 20-byte hex address`);
  }
  return value.toLowerCase();
}

function decimals(value, name) {
  if (!Number.isInteger(value) || value < 0 || value > 36) {
    throw new RangeError(`${name} must be an integer from 0 to 36`);
  }
  return value;
}

function priceQ18(quoteAmount, baseAmount, baseDecimals, quoteDecimals) {
  if (baseAmount <= 0n || quoteAmount <= 0n) throw new RangeError('swap amounts must be positive');
  return (quoteAmount * (10n ** BigInt(baseDecimals)) * Q18) /
    (baseAmount * (10n ** BigInt(quoteDecimals)));
}

function decimalString(q18) {
  const whole = q18 / Q18;
  const fraction = (q18 % Q18).toString().padStart(18, '0').replace(/0+$/, '');
  return fraction ? `${whole}.${fraction}` : whole.toString();
}

function bucketFor(timestamp, timeframe) {
  const date = new Date(timestamp * 1000);
  if (timeframe === '1h') return Math.floor(timestamp / HOUR) * HOUR;
  if (timeframe === '1d') return Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()) / 1000;
  if (timeframe === '1w') {
    const midnight = Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()) / 1000;
    const mondayOffset = (date.getUTCDay() + 6) % 7;
    return midnight - mondayOffset * DAY;
  }
  if (timeframe === '1M') return Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), 1) / 1000;
  throw new RangeError('timeframe must be one of 1h, 1d, 1w, 1M');
}

function nextBucket(start, timeframe) {
  if (timeframe === '1h') return start + HOUR;
  if (timeframe === '1d') return start + DAY;
  if (timeframe === '1w') return start + 7 * DAY;
  const d = new Date(start * 1000);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1) / 1000;
}

/**
 * Build candles from confirmed canonical AMM swap events only. This is a pure indexer module:
 * the caller must decode logs from the configured pair, verify canonical block hashes and provide
 * confirmations from the chain adapter. It intentionally does not synthesize empty candles.
 *
 * Each event has: pairAddress, token0, token1, amount0In, amount1In, amount0Out, amount1Out,
 * blockNumber, blockTimestamp, blockHash, transactionHash, logIndex, confirmations, canonical.
 */
export function buildCandles(events, {
  pairAddress, token0, token1, baseTokenAddress, baseDecimals, quoteDecimals,
  timeframe, minimumConfirmations = 1,
}) {
  if (!Array.isArray(events)) throw new TypeError('events must be an array');
  if (!Number.isInteger(minimumConfirmations) || minimumConfirmations < 1) {
    throw new RangeError('minimumConfirmations must be a positive integer');
  }
  pairAddress = normalizeAddress(pairAddress, 'pairAddress');
  token0 = normalizeAddress(token0, 'token0');
  token1 = normalizeAddress(token1, 'token1');
  baseTokenAddress = normalizeAddress(baseTokenAddress, 'baseTokenAddress');
  baseDecimals = decimals(baseDecimals, 'baseDecimals');
  quoteDecimals = decimals(quoteDecimals, 'quoteDecimals');
  if (token0 === token1 || (baseTokenAddress !== token0 && baseTokenAddress !== token1)) {
    throw new Error('pair token identities are inconsistent');
  }
  if (!['1h', '1d', '1w', '1M'].includes(timeframe)) {
    throw new RangeError('timeframe must be one of 1h, 1d, 1w, 1M');
  }

  const baseIsToken0 = baseTokenAddress === token0;
  const expectedQuote = baseIsToken0 ? token1 : token0;
  const seen = new Map();
  const swaps = [];

  for (const event of events) {
    if (!event || normalizeAddress(event.pairAddress, 'event.pairAddress') !== pairAddress) continue;
    if (event.canonical !== true) continue;
    if (!Number.isInteger(event.confirmations) || event.confirmations < minimumConfirmations) continue;
    if (!Number.isSafeInteger(event.blockNumber) || event.blockNumber < 0 ||
        !Number.isSafeInteger(event.blockTimestamp) || event.blockTimestamp <= 0 ||
        !Number.isSafeInteger(event.logIndex) || event.logIndex < 0) {
      throw new TypeError('event blockNumber, blockTimestamp and logIndex must be valid non-negative safe integers');
    }
    if (normalizeAddress(event.token0, 'event.token0') !== token0 ||
        normalizeAddress(event.token1, 'event.token1') !== token1) {
      throw new Error('event token order does not match the configured pair');
    }
    const blockHash = event.blockHash;
    const transactionHash = event.transactionHash;
    if (typeof blockHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(blockHash) ||
        typeof transactionHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(transactionHash)) {
      throw new TypeError('event blockHash and transactionHash must be 32-byte hex hashes');
    }

    const a0i = asBigInt(event.amount0In, 'amount0In');
    const a1i = asBigInt(event.amount1In, 'amount1In');
    const a0o = asBigInt(event.amount0Out, 'amount0Out');
    const a1o = asBigInt(event.amount1Out, 'amount1Out');
    let baseAmount; let quoteAmount;
    if (baseIsToken0) {
      if (a0i > 0n && a1o > 0n && a1i === 0n && a0o === 0n) {
        baseAmount = a0i; quoteAmount = a1o;
      } else if (a1i > 0n && a0o > 0n && a0i === 0n && a1o === 0n) {
        baseAmount = a0o; quoteAmount = a1i;
      } else continue;
    } else {
      if (a1i > 0n && a0o > 0n && a0i === 0n && a1o === 0n) {
        baseAmount = a1i; quoteAmount = a0o;
      } else if (a0i > 0n && a1o > 0n && a1i === 0n && a0o === 0n) {
        baseAmount = a1o; quoteAmount = a0i;
      } else continue;
    }
    if (baseAmount <= 0n || quoteAmount <= 0n) continue;

    const id = `${blockHash.toLowerCase()}:${transactionHash.toLowerCase()}:${event.logIndex}`;
    const normalized = {
      id, blockNumber: event.blockNumber, blockTimestamp: event.blockTimestamp,
      logIndex: event.logIndex, price: priceQ18(quoteAmount, baseAmount, baseDecimals, quoteDecimals),
      baseVolume: baseAmount, quoteVolume: quoteAmount,
    };
    const duplicate = seen.get(id);
    if (duplicate) {
      if (duplicate.price !== normalized.price || duplicate.baseVolume !== normalized.baseVolume ||
          duplicate.quoteVolume !== normalized.quoteVolume) throw new Error('duplicate log identity has conflicting swap data');
      continue;
    }
    seen.set(id, normalized);
    swaps.push(normalized);
  }

  swaps.sort((a, b) => a.blockNumber - b.blockNumber || a.logIndex - b.logIndex || a.id.localeCompare(b.id));
  const candles = new Map();
  for (const swap of swaps) {
    const start = bucketFor(swap.blockTimestamp, timeframe);
    let candle = candles.get(start);
    if (!candle) {
      candle = {
        timeframe, startTime: start, endTime: nextBucket(start, timeframe),
        openQ18: swap.price, highQ18: swap.price, lowQ18: swap.price, closeQ18: swap.price,
        baseVolumeAtoms: 0n, quoteVolumeAtoms: 0n, tradeCount: 0,
        firstBlock: swap.blockNumber, lastBlock: swap.blockNumber,
        firstLogIndex: swap.logIndex, lastLogIndex: swap.logIndex,
      };
      candles.set(start, candle);
    }
    candle.highQ18 = candle.highQ18 > swap.price ? candle.highQ18 : swap.price;
    candle.lowQ18 = candle.lowQ18 < swap.price ? candle.lowQ18 : swap.price;
    candle.closeQ18 = swap.price;
    candle.baseVolumeAtoms += swap.baseVolume;
    candle.quoteVolumeAtoms += swap.quoteVolume;
    candle.tradeCount += 1;
    candle.lastBlock = swap.blockNumber;
    candle.lastLogIndex = swap.logIndex;
  }

  return [...candles.values()].sort((a, b) => a.startTime - b.startTime).map(c => ({
    timeframe: c.timeframe,
    startTime: c.startTime,
    endTime: c.endTime,
    open: decimalString(c.openQ18), high: decimalString(c.highQ18),
    low: decimalString(c.lowQ18), close: decimalString(c.closeQ18),
    baseVolumeAtoms: c.baseVolumeAtoms.toString(), quoteVolumeAtoms: c.quoteVolumeAtoms.toString(),
    tradeCount: c.tradeCount, firstBlock: c.firstBlock, lastBlock: c.lastBlock,
    firstLogIndex: c.firstLogIndex, lastLogIndex: c.lastLogIndex,
  }));
}

export function candleSourceLabel({ chainName, chainId, pairAddress, quoteTokenAddress, minimumConfirmations }) {
  if (!chainName || !Number.isSafeInteger(chainId) || !pairAddress || !quoteTokenAddress ||
      !Number.isInteger(minimumConfirmations) || minimumConfirmations < 1) {
    throw new TypeError('candle source metadata must identify the chain, pair, quote asset and confirmation policy');
  }
  return { chainName, chainId, pairAddress: normalizeAddress(pairAddress, 'pairAddress'),
    quoteTokenAddress: normalizeAddress(quoteTokenAddress, 'quoteTokenAddress'),
    minimumConfirmations, dataKind: 'canonical-confirmed-swaps', synthetic: false };
}
