import process from "node:process";
import { JsonRpcProvider, Wallet, ContractFactory, getAddress } from "ethers";
import { compileAsset } from "./compile.mjs";
import { assertSupportedTestnetChainId } from "./deployment-policy.mjs";

function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error("Missing required environment variable: " + name);
  return value;
}
function isAddress(value, name) {
  try { return getAddress(value); }
  catch { throw new Error(name + " must be a valid EVM address"); }
}

// Apply the chain allowlist before reading credentials, touching an RPC, or compiling.
const expectedChainId = BigInt(required("EXPECTED_CHAIN_ID"));
assertSupportedTestnetChainId(expectedChainId);
const rpcUrl = required("RPC_URL");
const privateKey = required("DEPLOYER_PRIVATE_KEY");
const name = required("TOKEN_NAME");
const symbol = required("TOKEN_SYMBOL");
const founder = isAddress(required("FOUNDER_TREASURY"), "FOUNDER_TREASURY");
const security = isAddress(required("SECURITY_RESERVE"), "SECURITY_RESERVE");
const publicGoods = isAddress(required("PUBLIC_GOODS_TREASURY"), "PUBLIC_GOODS_TREASURY");

if (new Set([founder.toLowerCase(), security.toLowerCase(), publicGoods.toLowerCase()]).size !== 3) {
  throw new Error("Allocation addresses must be three distinct wallets/contracts.");
}
if (name.length < 1 || name.length > 32 || symbol.length < 1 || symbol.length > 16) {
  throw new Error("Name must be 1-32 chars and symbol 1-16 chars; public branding remains owner/legal review pending.");
}

const provider = new JsonRpcProvider(rpcUrl, Number(expectedChainId), { staticNetwork: true });
try {
  const network = await provider.getNetwork();
  if (network.chainId !== expectedChainId) {
    throw new Error("Safety stop: RPC chainId=" + network.chainId + " differs from EXPECTED_CHAIN_ID=" + expectedChainId);
  }
  const deployer = new Wallet(privateKey, provider);
  const asset = compileAsset();
  const factory = new ContractFactory(asset.abi, asset.bytecode, deployer);
  const deployment = await factory.deploy(name, symbol, founder, security, publicGoods);
  const tx = deployment.deploymentTransaction();
  process.stdout.write("submitted_testnet_deployment_tx=" + tx.hash + "\n");
  await deployment.waitForDeployment();
  const address = await deployment.getAddress();
  const code = await provider.getCode(address);
  if (code === "0x") throw new Error("Deployment returned an address without contract bytecode");
  const totalSupply = await deployment.totalSupply();
  const maxSupply = await deployment.MAX_SUPPLY();
  if (totalSupply !== maxSupply) throw new Error("Post-deployment supply invariant failed");
  process.stdout.write(JSON.stringify({
    status: "TESTNET_DEPLOYMENT_VERIFIED",
    chainId: Number(expectedChainId),
    contractAddress: address,
    transactionHash: tx.hash,
    deployerAddress: await deployer.getAddress(),
    founderTreasury: founder,
    securityReserve: security,
    publicGoodsTreasury: publicGoods,
    totalSupplyRaw: totalSupply.toString(),
    maxSupplyRaw: maxSupply.toString(),
    compiler: asset.compilerVersion,
    productionApproval: false,
    caveat: "Separate EVM test asset only; not the native L1 coin. Do not use for sale or real funds."
  }, null, 2) + "\n");
} finally {
  await provider.destroy();
}
