import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ContractFactory, JsonRpcProvider, parseUnits } from "ethers";
import { compileAsset, projectRoot } from "../scripts/compile.mjs";
import { assertSupportedTestnetChainId } from "../scripts/deployment-policy.mjs";

assert.doesNotThrow(() => assertSupportedTestnetChainId(84532n));
assert.doesNotThrow(() => assertSupportedTestnetChainId(11155111n));
for (const chainId of [1n, 8453n, 31337n, 1337n]) {
  assert.throws(() => assertSupportedTestnetChainId(chainId), /only permits Base Sepolia/);
}

function findFreePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        server.close();
        reject(new Error("Unable to select a local test port"));
        return;
      }
      const port = address.port;
      server.close(error => error ? reject(error) : resolve(port));
    });
  });
}

async function startLocalEvm(port) {
  const cli = path.join(projectRoot, "node_modules", "hardhat", "dist", "src", "cli.js");
  const child = spawn(process.execPath, [
    cli, "node", "--hostname", "127.0.0.1", "--port", String(port),
    "--chain-id", "31337", "--chain-type", "l1"
  ], { cwd: projectRoot, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });

  let started = false;
  let safeError = "";
  let settle;
  const ready = new Promise((resolve, reject) => {
    settle = { resolve, reject };
    const timer = setTimeout(() => reject(new Error("Local EDR server startup timed out")), 20000);
    const onReady = () => { clearTimeout(timer); started = true; resolve(); };
    const ingest = chunk => {
      const line = chunk.toString();
      if (line.includes("Started HTTP and WebSocket JSON-RPC server")) onReady();
      if (!started && /Error|ERROR|Cannot|failed/i.test(line)) safeError = "Hardhat EDR startup reported an error";
    };
    child.stdout.on("data", ingest);
    child.stderr.on("data", ingest);
    child.once("error", () => { clearTimeout(timer); reject(new Error("Hardhat EDR process failed to start")); });
    child.once("exit", code => {
      if (!started) { clearTimeout(timer); reject(new Error(safeError || "Hardhat EDR exited before ready (code " + code + ")")); }
    });
  });

  try {
    await ready;
    return child;
  } catch (error) {
    child.kill();
    throw error;
  }
}

const asset = compileAsset();
const port = await findFreePort();
const localNode = await startLocalEvm(port);
const provider = new JsonRpcProvider("http://127.0.0.1:" + port, 31337, { staticNetwork: true });

try {
  const network = await provider.getNetwork();
  assert.equal(network.chainId, 31337n, "only ephemeral local chain is used");
  const deployer = await provider.getSigner(0);
  const founder = await provider.getSigner(1);
  const security = await provider.getSigner(2);
  const publicGoods = await provider.getSigner(3);
  const buyer = await provider.getSigner(4);
  const founderAddress = await founder.getAddress();
  const securityAddress = await security.getAddress();
  const publicGoodsAddress = await publicGoods.getAddress();
  const buyerAddress = await buyer.getAddress();
  const factory = new ContractFactory(asset.abi, asset.bytecode, deployer);
  const token = await factory.deploy(
    "Qanvoryx Launch Candidate", "QX",
    founderAddress, securityAddress, publicGoodsAddress
  );
  await token.waitForDeployment();

  const unit = 10n ** 18n;
  const founderAmount = 4_000_000_000n * unit;
  const securityAmount = 3_000_000_000n * unit;
  const publicGoodsAmount = 3_000_000_000n * unit;
  const maxSupply = 10_000_000_000n * unit;

  assert.equal(await token.decimals(), 18n);
  assert.equal(await token.name(), "Qanvoryx Launch Candidate");
  assert.equal(await token.symbol(), "QX");
  assert.equal(await token.MAX_SUPPLY(), maxSupply);
  assert.equal(await token.totalSupply(), maxSupply);
  assert.equal(await token.balanceOf(founderAddress), founderAmount);
  assert.equal(await token.balanceOf(securityAddress), securityAmount);
  assert.equal(await token.balanceOf(publicGoodsAddress), publicGoodsAmount);
  assert.equal(founderAmount * 100n / maxSupply, 40n);
  assert.equal(securityAmount + publicGoodsAmount + founderAmount, maxSupply);

  const beforeSupply = await token.totalSupply();
  const transferAmount = parseUnits("125", 18);
  await (await token.connect(founder).transfer(buyerAddress, transferAmount)).wait();
  assert.equal(await token.balanceOf(buyerAddress), transferAmount);
  assert.equal(await token.totalSupply(), beforeSupply);

  const approvalAmount = parseUnits("25", 18);
  await (await token.connect(buyer).approve(securityAddress, approvalAmount)).wait();
  await (await token.connect(security).transferFrom(buyerAddress, publicGoodsAddress, approvalAmount)).wait();
  assert.equal(await token.balanceOf(publicGoodsAddress), publicGoodsAmount + approvalAmount);
  assert.equal(await token.balanceOf(buyerAddress), transferAmount - approvalAmount);
  assert.equal(await token.allowance(buyerAddress, securityAddress), 0n);
  assert.equal(await token.totalSupply(), beforeSupply);

  const functionNames = asset.abi.filter(item => item.type === "function").map(item => item.name);
  for (const forbidden of ["mint", "burn", "owner", "pause", "unpause", "setFee", "blacklist", "upgradeTo", "rescueTokens"]) {
    assert.ok(!functionNames.includes(forbidden), "unexpected privileged function in ABI: " + forbidden);
  }

  await assert.rejects(async () => {
    const bad = await factory.deploy("Bad", "BAD", founderAddress, founderAddress, publicGoodsAddress);
    await bad.waitForDeployment();
  }, "duplicate allocations must revert");
  await assert.rejects(async () => {
    const bad = await factory.deploy(
      "Bad", "BAD", "0x0000000000000000000000000000000000000000",
      securityAddress, publicGoodsAddress
    );
    await bad.waitForDeployment();
  }, "zero allocation address must revert");

  process.stdout.write([
    "LOCAL_EVM_FIXED_SUPPLY_ASSET_TEST=PASS",
    "checks=exact_10B_supply,40_30_30_allocations,erc20_transfer,approve_transferFrom,no_supply_change,no_privileged_mint,zero_and_duplicate_address_rejection,testnet_chain_allowlist",
    "engine=Hardhat_3_EDR",
    "chain_id=31337 (ephemeral local only)",
    "test_contract_not_deployed_to_public_chain=true"
  ].join("\n") + "\n");
} finally {
  await provider.destroy();
  localNode.kill();
}
