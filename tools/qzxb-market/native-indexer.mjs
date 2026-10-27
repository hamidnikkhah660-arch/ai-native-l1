import { buildNativeCandles } from './native-candles.mjs';

const MAX_BLOCKS_PER_PAGE = 8;

function validateRpcUrl(value) {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password ||
      url.search || url.hash) {
    throw new TypeError('rpcUrl must be an HTTP(S) URL without credentials, query, or fragment');
  }
  return url.toString().replace(/\/+$/, '');
}

/**
 * Fetch the node's canonical native swap history in bounded pages and build candles.
 * This adapter targets the local/loopback candidate RPC. It fails closed if the tip or reorg
 * counter changes while pages are being read; callers should restart the whole read after a reorg.
 */
export async function fetchNativeCandles({
  rpcUrl,
  pairId,
  baseTokenId,
  quoteTokenId,
  baseDecimals,
  quoteDecimals,
  timeframe,
  minimumConfirmations = 6,
  maxPages = 128,
  fetchImpl = globalThis.fetch,
}) {
  const baseUrl = validateRpcUrl(rpcUrl);
  if (typeof fetchImpl !== 'function') throw new TypeError('fetchImpl must be a function');
  if (!Number.isInteger(minimumConfirmations) || minimumConfirmations < 1 || minimumConfirmations > 1024) {
    throw new RangeError('minimumConfirmations must be between 1 and 1024');
  }
  if (!Number.isInteger(maxPages) || maxPages < 1 || maxPages > 4096) {
    throw new RangeError('maxPages must be between 1 and 4096');
  }

  const blocks = [];
  let cursor;
  let sourceIdentity;
  let pagesFetched = 0;
  let historyComplete = false;

  while (pagesFetched < maxPages) {
    const query = new URLSearchParams();
    query.set('min_confirmations', String(minimumConfirmations));
    query.set('limit_blocks', String(MAX_BLOCKS_PER_PAGE));
    if (cursor !== undefined) query.set('before_height', String(cursor));
    const response = await fetchImpl(baseUrl + '/v1/amm/swaps?' + query.toString(), {
      method: 'GET',
      headers: { accept: 'application/json' },
    });
    if (!response || response.ok !== true) {
      throw new Error('native AMM RPC request failed with HTTP status ' + (response && response.status));
    }
    const data = await response.json();
    if (!data || data.ok !== true || data.read_only !== true ||
        typeof data.network_id !== 'string' || typeof data.genesis_id !== 'string' ||
        typeof data.profile_id !== 'string' || typeof data.tip !== 'string' ||
        !Number.isSafeInteger(data.height) || !Number.isSafeInteger(data.reorg_count) ||
        !Number.isSafeInteger(data.retained_base_height) || !Array.isArray(data.blocks)) {
      throw new Error('native AMM RPC response does not match the expected candidate schema');
    }
    const identity = {
      network_id: data.network_id,
      genesis_id: data.genesis_id,
      profile_id: data.profile_id,
      height: data.height,
      tip: data.tip,
      reorg_count: data.reorg_count,
      retained_base_height: data.retained_base_height,
      mainnet: data.mainnet === true,
      public_launch_approved: data.public_launch_approved === true,
    };
    if (!sourceIdentity) {
      sourceIdentity = identity;
    } else {
      for (const key of Object.keys(sourceIdentity)) {
        if (sourceIdentity[key] !== identity[key]) {
          throw new Error('canonical node identity changed during pagination; restart indexing');
        }
      }
    }
    if (data.min_confirmations !== minimumConfirmations ||
        data.finality_model !== 'probabilistic_pow_confirmations') {
      throw new Error('native AMM RPC confirmation policy mismatch');
    }
    pagesFetched += 1;
    if (data.blocks.length > MAX_BLOCKS_PER_PAGE) throw new Error('native AMM RPC exceeded the bounded page size');
    let oldestHeight;
    for (const block of data.blocks) {
      if (!Number.isSafeInteger(block.height)) throw new Error('native AMM RPC returned an invalid block height');
      if (oldestHeight === undefined || block.height < oldestHeight) oldestHeight = block.height;
      blocks.push(block);
    }
    if (data.blocks.length === 0) {
      if (sourceIdentity.height - sourceIdentity.retained_base_height >= minimumConfirmations) {
        throw new Error('native AMM RPC returned an empty page before the retained history boundary');
      }
      historyComplete = true;
      break;
    }
    if (oldestHeight <= sourceIdentity.retained_base_height + 1) {
      historyComplete = true;
      break;
    }
    if (oldestHeight >= (cursor === undefined ? Number.POSITIVE_INFINITY : cursor)) {
      throw new Error('native AMM RPC pagination cursor failed to move backwards');
    }
    cursor = oldestHeight;
  }

  if (!historyComplete) {
    throw new Error('native AMM history exceeds maxPages; increase maxPages and retry to avoid incomplete candles');
  }

  const candles = buildNativeCandles(blocks, {
    pairId,
    baseTokenId,
    quoteTokenId,
    baseDecimals,
    quoteDecimals,
    timeframe,
    minimumConfirmations,
  });
  return {
    candles,
    source: {
      dataKind: 'canonical-native-amm-swaps',
      synthetic: false,
      networkId: sourceIdentity.network_id,
      genesisId: sourceIdentity.genesis_id,
      profileId: sourceIdentity.profile_id,
      canonicalTip: sourceIdentity.tip,
      height: sourceIdentity.height,
      reorgCount: sourceIdentity.reorg_count,
      retainedBaseHeight: sourceIdentity.retained_base_height,
      minimumConfirmations,
      finalityModel: 'probabilistic_pow_confirmations',
      pagesFetched,
      historyComplete,
      mainnet: sourceIdentity.mainnet,
      publicLaunchApproved: sourceIdentity.public_launch_approved,
    },
  };
}
