import { fetchNativeCandles } from '../tools/qzxb-market/native-indexer.mjs';

const args = process.argv.slice(2);
if (args.length !== 4) {
  console.error('usage: cp0441_native_candle_check.mjs RPC_URL PAIR_ID QZXB_ASSET_ID QUSDT_TEST_ASSET_ID');
  process.exit(2);
}
const [rpcUrl, pairId, nativeTokenId, quoteTokenId] = args;
for (const timeframe of ['1h', '1d', '1w', '1M']) {
  const { candles, source } = await fetchNativeCandles({
    rpcUrl,
    pairId,
    baseTokenId: nativeTokenId,
    quoteTokenId,
    baseDecimals: 8,
    quoteDecimals: 6,
    timeframe,
    minimumConfirmations: 1,
    maxPages: 128,
  });
  if (source.dataKind !== 'canonical-native-amm-swaps' ||
      !source.historyComplete || source.mainnet !== false ||
      source.publicLaunchApproved !== false ||
      source.networkId.toLowerCase() !== 'd4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4') {
    throw new Error('native candle source is incomplete or does not match the explicit loopback test network');
  }
  if (candles.length !== 1 || candles[0].tradeCount !== 1) {
    throw new Error('expected exactly one confirmed canonical QZXB/QUSDT-testnet candle for ' + timeframe);
  }
  const candle = candles[0];
  if (candle.open !== candle.close || candle.high !== candle.low ||
      BigInt(candle.baseVolumeAtoms) <= 0n || BigInt(candle.quoteVolumeAtoms) <= 0n) {
    throw new Error('OHLC, orientation, or atom volume invalid for ' + timeframe);
  }
  console.log('CP-0441_CANDLE_PASS timeframe=' + timeframe +
    ' trades=' + candle.tradeCount + ' open=' + candle.open +
    ' high=' + candle.high + ' low=' + candle.low + ' close=' + candle.close +
    ' base_volume_atoms=' + candle.baseVolumeAtoms +
    ' quote_volume_atoms=' + candle.quoteVolumeAtoms);
}
console.log('CP-0441_HOURLY_DAILY_WEEKLY_MONTHLY_CANDLES_PASS quote_asset=QUSDT_TESTNET_UNBACKED');
