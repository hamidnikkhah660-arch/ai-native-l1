export const ALLOWED_TESTNET_CHAIN_IDS = new Set([84532n, 11155111n]);

export function assertSupportedTestnetChainId(chainId) {
  if (!ALLOWED_TESTNET_CHAIN_IDS.has(BigInt(chainId))) {
    throw new Error("Safety stop: this script only permits Base Sepolia (84532) or Ethereum Sepolia (11155111). It cannot deploy to a mainnet.");
  }
}
