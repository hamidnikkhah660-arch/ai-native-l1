const Q18 = 10n ** 18n;
const DAY = 86_400;
const HOUR = 3_600;

function normalizeId(value, name) {
  if (typeof value !== 'string') throw new TypeError(name + ' must be a 32-byte hex ID');
  const raw = value.startsWith('0x') || value.startsWith('0X') ? value.slice(2) : value;
  if (!/^[0-9a-fA-F]{64}$/.test(raw)) throw new TypeError(name + ' must be a 32-byte hex ID');
  return raw.toLowerCase();
}

function amount(value, name) {
  try {
    const out = typeof value === 'bigint' ? value : BigInt(value);
    if (out < 0n) throw new Error('negative');
    return out;
  } catch {
    throw new TypeError(name + ' must be a non-negative integer');
  }
}

function decimals(value, name) {
  if (!Number.isInteger(value) || value < 0 || value > 36) {
    throw new RangeError(name + ' must be an integer from 0 to 36');
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
  return fraction ? whole.toString() + '.' + fraction : whole.toString();
}

function bucketFor(timestamp, timeframe) {
  const date = new Date(timestamp * 1000);
  if (timeframe === '1h') return Math.floor(timestamp / HOUR) * HOUR;
  if (timeframe === '1d') return Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()) / 1000;
  if (timeframe === '1w') {
    const midnight = Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()) / 1000;
    return midnight - ((date.getUTCDay() + 6) % 7) * DAY;
  }
  if (timeframe === '1M') return Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), 1) / 1000;
  throw new RangeError('timeframe must be one of 1h, 1d, 1w, 1M');
}

function nextBucket(start, timeframe) {
  if (timeframe === '1h') return start + HOUR;
  if (timeframe === '1d') return start + DAY;
  if (timeframe === '1w') return start + 7 * DAY;
  const date = new Date(start * 1000);
  return Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + 1, 1) / 1000;
}

/**
 * Build OHLC candles from the QZBE native AMM read-only endpoint response.
 * Blocks must come from /v1/amm/swaps and include a canonical flag and confirmations.
 * PoW confirmation depth is probabilistic, not deterministic protocol finality. Consumers must
 * restart/rewind indexed pages when the endpoint's canonical tip or a previously seen block hash changes.
 */
export function buildNativeCandles(blocks, {
  pairId, baseTokenId, quoteTokenId, baseDecimals, quoteDecimals,
  timeframe, minimumConfirmations = 6,
}) {
  if (!Array.isArray(blocks)) throw new TypeError('blocks must be an array');
  if (!Number.isInteger(minimumConfirmations) || minimumConfirmations < 1) {
    throw new RangeError('minimumConfirmations must be a positive integer');
  }
  pairId = normalizeId(pairId, 'pairId');
  baseTokenId = normalizeId(baseTokenId, 'baseTokenId');
  quoteTokenId = normalizeId(quoteTokenId, 'quoteTokenId');
  baseDecimals = decimals(baseDecimals, 'baseDecimals');
  quoteDecimals = decimals(quoteDecimals, 'quoteDecimals');
  if (baseTokenId === quoteTokenId) throw new Error('base and quote token IDs must differ');
  if (!['1h', '1d', '1w', '1M'].includes(timeframe)) {
    throw new RangeError('timeframe must be one of 1h, 1d, 1w, 1M');
  }

  const canonicalHeights = new Map();
  const seenSwaps = new Map();
  const swaps = [];

  for (const block of blocks) {
    if (!block || block.canonical !== true) continue;
    if (!Number.isSafeInteger(block.height) || block.height < 0 ||
        !Number.isSafeInteger(block.timestamp) || block.timestamp <= 0 ||
        !Number.isSafeInteger(block.confirmations) || block.confirmations < 0) {
      throw new TypeError('canonical block height, timestamp and confirmations must be valid integers');
    }
    const blockHash = normalizeId(block.block_hash, 'block_hash');
    const oldHash = canonicalHeights.get(block.height);
    if (oldHash && oldHash !== blockHash) {
      throw new Error('conflicting canonical block hashes at the same height; rewind after reorg');
    }
    canonicalHeights.set(block.height, blockHash);
    if (block.confirmations < minimumConfirmations) continue;
    if (!Array.isArray(block.swaps)) throw new TypeError('block swaps must be an array');

    for (const event of block.swaps) {
      if (!event || !Number.isSafeInteger(event.operation_index) || event.operation_index < 0) {
        throw new TypeError('operation_index must be a non-negative safe integer');
      }
      if (normalizeId(event.pair_id, 'event.pair_id') !== pairId) continue;
      const tokenIn = normalizeId(event.token_in, 'event.token_in');
      const tokenOut = normalizeId(event.token_out, 'event.token_out');
      const amountIn = amount(event.amount_in_atoms, 'amount_in_atoms');
      const amountOut = amount(event.amount_out_atoms, 'amount_out_atoms');
      if (tokenIn === baseTokenId && tokenOut === quoteTokenId) {
        // Base asset sold for quote asset.
      } else if (tokenIn === quoteTokenId && tokenOut === baseTokenId) {
        // Quote asset sold for base asset.
      } else {
        throw new Error('swap token IDs do not match the configured base/quote pair');
      }
      if (amountIn === 0n || amountOut === 0n) throw new RangeError('swap amounts must be positive');

      const id = blockHash + ':' + event.operation_index;
      const baseAmount = tokenIn === baseTokenId ? amountIn : amountOut;
      const quoteAmount = tokenIn === quoteTokenId ? amountIn : amountOut;
      const normalized = {
        id,
        height: block.height,
        timestamp: block.timestamp,
        operationIndex: event.operation_index,
        price: priceQ18(quoteAmount, baseAmount, baseDecimals, quoteDecimals),
        baseVolume: baseAmount,
        quoteVolume: quoteAmount,
      };
      const duplicate = seenSwaps.get(id);
      if (duplicate) {
        if (duplicate.height !== normalized.height || duplicate.timestamp !== normalized.timestamp ||
            duplicate.price !== normalized.price || duplicate.baseVolume !== normalized.baseVolume ||
            duplicate.quoteVolume !== normalized.quoteVolume) {
          throw new Error('duplicate native swap identity has conflicting contents');
        }
        continue;
      }
      seenSwaps.set(id, normalized);
      swaps.push(normalized);
    }
  }

  swaps.sort((a, b) => a.height - b.height || a.operationIndex - b.operationIndex || a.id.localeCompare(b.id));
  const candles = new Map();
  for (const swap of swaps) {
    const start = bucketFor(swap.timestamp, timeframe);
    let candle = candles.get(start);
    if (!candle) {
      candle = {
        timeframe,
        startTime: start,
        endTime: nextBucket(start, timeframe),
        openQ18: swap.price,
        highQ18: swap.price,
        lowQ18: swap.price,
        closeQ18: swap.price,
        baseVolumeAtoms: 0n,
        quoteVolumeAtoms: 0n,
        tradeCount: 0,
        firstBlock: swap.height,
        lastBlock: swap.height,
        firstOperationIndex: swap.operationIndex,
        lastOperationIndex: swap.operationIndex,
      };
      candles.set(start, candle);
    }
    candle.highQ18 = candle.highQ18 > swap.price ? candle.highQ18 : swap.price;
    candle.lowQ18 = candle.lowQ18 < swap.price ? candle.lowQ18 : swap.price;
    candle.closeQ18 = swap.price;
    candle.baseVolumeAtoms += swap.baseVolume;
    candle.quoteVolumeAtoms += swap.quoteVolume;
    candle.tradeCount += 1;
    candle.lastBlock = swap.height;
    candle.lastOperationIndex = swap.operationIndex;
  }

  return [...candles.values()].sort((a, b) => a.startTime - b.startTime).map(c => ({
    timeframe: c.timeframe,
    startTime: c.startTime,
    endTime: c.endTime,
    open: decimalString(c.openQ18),
    high: decimalString(c.highQ18),
    low: decimalString(c.lowQ18),
    close: decimalString(c.closeQ18),
    baseVolumeAtoms: c.baseVolumeAtoms.toString(),
    quoteVolumeAtoms: c.quoteVolumeAtoms.toString(),
    tradeCount: c.tradeCount,
    firstBlock: c.firstBlock,
    lastBlock: c.lastBlock,
    firstOperationIndex: c.firstOperationIndex,
    lastOperationIndex: c.lastOperationIndex,
  }));
}
