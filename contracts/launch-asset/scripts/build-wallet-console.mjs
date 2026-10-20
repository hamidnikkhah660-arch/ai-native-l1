import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { compileAsset, projectRoot } from "./compile.mjs";

const repoRoot = path.resolve(projectRoot, "..", "..");
const templatePath = path.join(repoRoot, "tools", "evm_testnet_wallet.template.html");
const outputPath = path.join(repoRoot, "tools", "evm_testnet_wallet.html");
const template = fs.readFileSync(templatePath, "utf8");
const runtimeMarker = "__EXPECTED_RUNTIME_CODE__";
const creationMarker = "__CREATION_BYTECODE__";
if (template.split(runtimeMarker).length !== 2 || template.split(creationMarker).length !== 2) {
  throw new Error("Wallet template must contain exactly one runtime-code marker and one creation-bytecode marker");
}
const asset = compileAsset();
const runtime = asset.deployedBytecode.toLowerCase();
const creation = asset.bytecode.toLowerCase();
if (!/^0x[0-9a-f]+$/.test(runtime) || !/^0x[0-9a-f]+$/.test(creation)) {
  throw new Error("Compiled runtime/creation bytecode is not valid hex");
}
const html = template.replace(runtimeMarker, runtime).replace(creationMarker, creation);
fs.writeFileSync(outputPath, html, { encoding: "utf8", flag: "w" });
process.stdout.write(JSON.stringify({
  status: "WALLET_CONSOLE_BUILD_PASS",
  outputPath: path.relative(repoRoot, outputPath),
  embeddedRuntimeBytes: (runtime.length - 2) / 2,
  embeddedCreationBytes: (creation.length - 2) / 2,
  compilerVersion: asset.compilerVersion,
  allowedNetworks: ["Base Sepolia 84532", "Ethereum Sepolia 11155111"],
  mainnetEnabled: false,
  privateKeyHandling: "never requested or stored"
}, null, 2) + "\n");
